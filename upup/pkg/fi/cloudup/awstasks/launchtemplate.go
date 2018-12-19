/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package awstasks

import (
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
	"time"

	"k8s.io/kops/upup/pkg/fi"
	"k8s.io/kops/upup/pkg/fi/cloudup/awsup"
	"k8s.io/kops/upup/pkg/fi/cloudup/cloudformation"
	"k8s.io/kops/upup/pkg/fi/cloudup/terraform"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/autoscaling"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/golang/glog"
	"k8s.io/apimachinery/pkg/util/sets"
)

// LaunchTemplate defines the specificate for a template
type LaunchTemplate struct {
	// LaunchTemplate is a reference to a launch configuration
	*LaunchConfiguration

	//
}

var (
	_ fi.CompareWithID     = &LaunchTemplate{}
	_ fi.ProducesDeletions = &LaunchTemplate{}
)

// RenderAWS is responsible for performing creating / updating the launch template
func (e *LaunchTemplate) RenderAWS(t *awsup.AWSAPITarget, a, ep, changes *LaunchTemplate) error {
	// @step: generate the name prefix - the name and build timestamp
	name := *ep.Name + "-" + fi.BuildTimestampString()

	// @step: resolve the image id to an AMI for us
	image, err := t.Cloud.ResolveImage(fi.StringValue(ep.ImageID))
	if err != nil {
		return err
	}

	// @step: lets build the launch template input
	lc := &ec2.RequestLaunchTemplateData{
		DisableApiTermination:             fi.Bool(false),
		EbsOptimized:                      ep.RootVolumeOptimization,
		ImageId:                           image.ImageId,
		InstanceInitiatedShutdownBehavior: aws.String(ec2.ShutdownBehaviorStop),
		InstanceType:                      ep.InstanceType,
	}
	input := &ec2.CreateLaunchTemplateInput{
		LaunchTemplateData: lc,
		LaunchTemplateName: aws.String(name),
	}
	// @step: add the ssh key
	if ep.SSHKey != nil {
		lc.KeyName = ep.SSHKey.Name
	}
	// @step: add the security groups
	list := []*string{}
	for _, sg := range ep.SecurityGroups {
		lc.SecurityGroups = append(lc.SecurityGroups, sg.ID)
	}

	// @step: add the the actual block device mappings
	rootDevices, err := ep.buildRootDevice(t.Cloud)
	if err != nil {
		return err
	}
	ephemeralDevices, err := buildEphemeralDevices(ep.InstanceType)
	if err != nil {
		return err
	}
	if len(rootDevices) != 0 || len(ephemeralDevices) != 0 {
		lc.BlockDeviceMappings = []*autoscaling.BlockDeviceMapping{}
		for device, bdm := range rootDevices {
			lc.BlockDeviceMappings = append(lc.BlockDeviceMappings, bdm.ToAutoscaling(device))
		}
		for device, bdm := range ephemeralDevices {
			lc.BlockDeviceMappings = append(lc.BlockDeviceMappings, bdm.ToAutoscaling(device))
		}
	}

	// @step: add the userdata
	if ep.UserData != nil {
		d, err := ep.UserData.AsBytes()
		if err != nil {
			return fmt.Errorf("error rendering LaunchTemplate UserData: %v", err)
		}
		lc.UserData = aws.String(base64.StdEncoding.EncodeToString(d))
	}

	// @step: add the iam instance profile
	if ep.IAMInstanceProfile != nil {
		lc.IamInstanceProfile = ep.IAMInstanceProfile.Name
	}

	// @step: set the instance monitoring
	lc.Monitoring = &ec2.LaunchTemplatesMonitoringRequest{Enabled: fi.Bool(false)}
	if ep.InstanceMonitoring != nil {
		lc.InstanceMonitoring = &autoscaling.InstanceMonitoring{Enabled: ep.InstanceMonitoring}
	}

	// @step: attempt to create the launch template

	attempt := 0
	maxAttempts := 10
	for {
		attempt++

		glog.V(8).Infof("AWS CreateLaunchTemplate %s", aws.StringValue(request.LaunchConfigurationName))
		_, err = t.Cloud.Autoscaling().CreateLaunchTemplate(request)
		if err == nil {
			break
		}

		if awsup.AWSErrorCode(err) == "ValidationError" {
			message := awsup.AWSErrorMessage(err)
			if strings.Contains(message, "not authorized") || strings.Contains(message, "Invalid IamInstance") {
				if attempt > maxAttempts {
					return fmt.Errorf("IAM instance profile not yet created/propagated (original error: %v)", message)
				}
				glog.V(4).Infof("got an error indicating that the IAM instance profile %q is not ready: %q", fi.StringValue(ep.IAMInstanceProfile.Name), message)
				glog.Infof("waiting for IAM instance profile %q to be ready", fi.StringValue(ep.IAMInstanceProfile.Name))
				time.Sleep(10 * time.Second)
				continue
			}
			glog.V(4).Infof("ErrorCode=%q, Message=%q", awsup.AWSErrorCode(err), awsup.AWSErrorMessage(err))
		}

		return fmt.Errorf("error creating AutoscalingLaunchTemplate: %v", err)
	}

	ep.ID = fi.String(launchConfigurationName)

	return nil
}

// Find is responsible for finding the launch template for us
func (e *LaunchTemplate) Find(c *fi.Context) (*LaunchTemplate, error) {
	// @step: get the latest launch template
	lt, err := e.findLatestLaunchTemplate(c)
	if err != nil {
		return lt, err
	}
	if lt == nil {
		return nil, nil
	}

	glog.V(2).Infof("found existing LaunchTemplate: %s", *lt.LaunchTemplateName)

	actual := &LaunchTemplate{
		AssociatePublicIP:      lt.AssociatePublicIpAddress,
		ID:                     lt.LaunchTemplateName,
		ImageID:                lt.ImageId,
		InstanceMonitoring:     lt.InstanceMonitoring.Enabled,
		InstanceType:           lt.InstanceType,
		Lifecycle:              e.Lifecycle,
		Name:                   e.Name,
		RootVolumeOptimization: lt.EbsOptimized,
		Tenancy:                lt.PlacementTenancy,
	}

	// @step: add the ssh if there is one
	if lt.KeyName != nil {
		actual.SSHKey = &SSHKey{Name: lt.KeyName}
	}
	// @step: add a instance if there is one
	if lt.IamInstanceProfile != nil {
		actual.IAMInstanceProfile = &IAMInstanceProfile{Name: lt.IamInstanceProfile}
	}
	// @step: add at the security groups
	sg := []*SecurityGroup{}
	for _, id := range lt.SecurityGroups {
		sg = append(sg, &SecurityGroup{ID: id})
	}
	sort.Sort(OrderSecurityGroupsById(sg))

	actual.SecurityGroups = sg

	// @step: find the root volume
	for _, b := range lt.BlockDeviceMappings {
		if b.Ebs == nil || b.Ebs.SnapshotId != nil {
			continue
		}
		actual.RootVolumeSize = b.Ebs.VolumeSize
		actual.RootVolumeType = b.Ebs.VolumeType
		actual.RootVolumeIops = b.Ebs.Iops
	}

	if lt.UserData != nil {
		ud, err := base64.StdEncoding.DecodeString(aws.StringValue(lt.UserData))
		if err != nil {
			return nil, fmt.Errorf("error decoding userdata: %s", err)
		}
		actual.UserData = fi.WrapResource(fi.NewStringResource(string(ud)))
	}

	// @step: to avoid spurious changes on ImageId
	if e.ImageID != nil && actual.ImageID != nil && *actual.ImageID != *e.ImageID {
		image, err := cloud.ResolveImage(*e.ImageID)
		if err != nil {
			glog.Warningf("unable to resolve image: %q: %v", *e.ImageID, err)
		} else if image == nil {
			glog.Warningf("unable to resolve image: %q: not found", *e.ImageID)
		} else if aws.StringValue(image.ImageId) == *actual.ImageID {
			glog.V(4).Infof("Returning matching ImageId as expected name: %q -> %q", *actual.ImageID, *e.ImageID)
			actual.ImageID = e.ImageID
		}
	}

	if e.ID == nil {
		e.ID = actual.ID
	}

	return actual, nil
}

// findAllLaunchTemplates returns all the launch templates
func (e *LaunchTemplate) findAllLaunchTemplates(c *fi.Context) ([]*ec2.LaunchTemplate, error) {
	var list []*ec2.LaunchTemplate
	var nextToken string

	for {
		input := &ec2.DescribeLaunchTemplatesInput{}
		if nextToken != "" {
			input.NextToken = aws.String(nextToken)
		}
		resp, err := cloud.EC2().DescribeLaunchTemplates(input)
		if err != nil {
			return list, err
		}
		if resp.NextToken == nil {
			break
		}
		nextToken = aws.StringValue(resp.NextToken)
	}

	return list, nil
}

// findLaunchTemplates returns a list of launch templates
func (e *LaunchTemplate) findLaunchTemplates(c *fi.Context) ([]*ec2.LaunchTemplate, error) {
	cloud := c.Cloud.(awsup.AWSCloud)
	prefix := *e.Name + "-"

	// @step: get a list of the launch templates
	list, err := e.findAllLaunchTemplates(c)
	if err != nil {
		return err
	}

	// @step: filter out the templates we are interested in
	var filtered []*ec2.LaunchTemplate
	for _, x := range list {
		if strings.HasPrefix(aws.StringValue(x.LaunchTemplateName), prefix) {
			filtered = append(filtered, x)
		}
	}

	// @step: we can sort the configurations in chronological order
	sort.Slice(filtered, func(i, j int) bool {
		ti := filtered[i].CreatedTime
		tj := filtered[j].CreatedTime
		if tj == nil {
			return true
		}
		if ti == nil {
			return false
		}
		return ti.UnixNano() < tj.UnixNano()
	})

	return filtered, nil
}

// findLatestLaunchTemplate returns the latest template
func (e *LaunchTemplate) findLatestLaunchTemplate(c *fi.Context) (*LaunchTemplate, error) {
	// @step: get a list of configuration
	configurations, err := e.findLaunchTemplates(c)
	if err != nil {
		return nil, err
	}
	if len(configurations) == 0 {
		return nil, nil
	}

	return configurations[len(configurations)-1], nil
}

// buildRootDevice is responsibel
func (e *LaunchTemplate) buildRootDevice(cloud awsup.AWSCloud) (map[string]*BlockDeviceMapping, error) {
	imageID := fi.StringValue(e.ImageID)
	image, err := cloud.ResolveImage(imageID)
	if err != nil {
		return nil, fmt.Errorf("unable to resolve image: %q: %v", imageID, err)
	} else if image == nil {
		return nil, fmt.Errorf("unable to resolve image: %q: not found", imageID)
	}

	rootDeviceName := aws.StringValue(image.RootDeviceName)

	blockDeviceMappings := make(map[string]*BlockDeviceMapping)

	rootDeviceMapping := &BlockDeviceMapping{
		EbsDeleteOnTermination: aws.Bool(true),
		EbsVolumeSize:          e.RootVolumeSize,
		EbsVolumeType:          e.RootVolumeType,
		EbsVolumeIops:          e.RootVolumeIops,
	}

	blockDeviceMappings[rootDeviceName] = rootDeviceMapping

	return blockDeviceMappings, nil
}

// Run is responsible for
func (e *LaunchTemplate) Run(c *fi.Context) error {
	e.Normalize()

	return fi.DefaultDeltaRunMethod(e, c)
}

//
func (e *LaunchTemplate) Normalize() {
	sort.Stable(OrderSecurityGroupsById(e.SecurityGroups))
}

func (s *LaunchTemplate) CheckChanges(a, e, changes *LaunchConfiguration) error {
	if e.ImageID == nil {
		return fi.RequiredField("ImageID")
	}
	if e.InstanceType == nil {
		return fi.RequiredField("InstanceType")
	}

	if a != nil {
		if e.Name == nil {
			return fi.RequiredField("Name")
		}
	}
	return nil
}

type terraformLaunchTemplate struct {
	NamePrefix               *string                 `json:"name_prefix,omitempty"`
	ImageID                  *string                 `json:"image_id,omitempty"`
	InstanceType             *string                 `json:"instance_type,omitempty"`
	KeyName                  *terraform.Literal      `json:"key_name,omitempty"`
	IAMInstanceProfile       *terraform.Literal      `json:"iam_instance_profile,omitempty"`
	SecurityGroups           []*terraform.Literal    `json:"security_groups,omitempty"`
	AssociatePublicIpAddress *bool                   `json:"associate_public_ip_address,omitempty"`
	UserData                 *terraform.Literal      `json:"user_data,omitempty"`
	RootBlockDevice          *terraformBlockDevice   `json:"root_block_device,omitempty"`
	EBSOptimized             *bool                   `json:"ebs_optimized,omitempty"`
	EphemeralBlockDevice     []*terraformBlockDevice `json:"ephemeral_block_device,omitempty"`
	Lifecycle                *terraform.Lifecycle    `json:"lifecycle,omitempty"`
	SpotPrice                *string                 `json:"spot_price,omitempty"`
	PlacementTenancy         *string                 `json:"placement_tenancy,omitempty"`
	InstanceMonitoring       *bool                   `json:"enable_monitoring,omitempty"`
}

type terraformBlockDevice struct {
	// For ephemeral devices
	DeviceName  *string `json:"device_name,omitempty"`
	VirtualName *string `json:"virtual_name,omitempty"`

	// For root
	VolumeType          *string `json:"volume_type,omitempty"`
	VolumeSize          *int64  `json:"volume_size,omitempty"`
	DeleteOnTermination *bool   `json:"delete_on_termination,omitempty"`
}

func (_ *LaunchTemplate) RenderTerraform(t *terraform.TerraformTarget, a, e, changes *LaunchConfiguration) error {
	cloud := t.Cloud.(awsup.AWSCloud)

	if e.ImageID == nil {
		return fi.RequiredField("ImageID")
	}
	image, err := cloud.ResolveImage(*e.ImageID)
	if err != nil {
		return err
	}

	tf := &terraformLaunchTemplate{
		NamePrefix:   fi.String(*e.Name + "-"),
		ImageID:      image.ImageId,
		InstanceType: e.InstanceType,
	}

	if e.SpotPrice != "" {
		tf.SpotPrice = aws.String(e.SpotPrice)
	}

	if e.SSHKey != nil {
		tf.KeyName = e.SSHKey.TerraformLink()
	}

	if e.Tenancy != nil {
		tf.PlacementTenancy = e.Tenancy
	}

	for _, sg := range e.SecurityGroups {
		tf.SecurityGroups = append(tf.SecurityGroups, sg.TerraformLink())
	}

	tf.AssociatePublicIpAddress = e.AssociatePublicIP

	tf.EBSOptimized = e.RootVolumeOptimization

	{
		rootDevices, err := e.buildRootDevice(cloud)
		if err != nil {
			return err
		}

		ephemeralDevices, err := buildEphemeralDevices(e.InstanceType)
		if err != nil {
			return err
		}

		if len(rootDevices) != 0 {
			if len(rootDevices) != 1 {
				return fmt.Errorf("unexpectedly found multiple root devices")
			}

			for _, bdm := range rootDevices {
				tf.RootBlockDevice = &terraformBlockDevice{
					VolumeType:          bdm.EbsVolumeType,
					VolumeSize:          bdm.EbsVolumeSize,
					DeleteOnTermination: fi.Bool(true),
				}
			}
		}

		if len(ephemeralDevices) != 0 {
			tf.EphemeralBlockDevice = []*terraformBlockDevice{}
			for _, deviceName := range sets.StringKeySet(ephemeralDevices).List() {
				bdm := ephemeralDevices[deviceName]
				tf.EphemeralBlockDevice = append(tf.EphemeralBlockDevice, &terraformBlockDevice{
					VirtualName: bdm.VirtualName,
					DeviceName:  fi.String(deviceName),
				})
			}
		}
	}

	if e.UserData != nil {
		tf.UserData, err = t.AddFile("aws_launch_configuration", *e.Name, "user_data", e.UserData)
		if err != nil {
			return err
		}
	}
	if e.IAMInstanceProfile != nil {
		tf.IAMInstanceProfile = e.IAMInstanceProfile.TerraformLink()
	}
	if e.InstanceMonitoring != nil {
		tf.InstanceMonitoring = e.InstanceMonitoring
	} else {
		tf.InstanceMonitoring = fi.Bool(false)
	}
	// So that we can update configurations
	tf.Lifecycle = &terraform.Lifecycle{CreateBeforeDestroy: fi.Bool(true)}

	return t.RenderResource("aws_launch_configuration", *e.Name, tf)
}

func (e *LaunchTemplate) TerraformLink() *terraform.Literal {
	return terraform.LiteralProperty("aws_launch_configuration", *e.Name, "id")
}

type cloudformationLaunchTemplate struct {
	AssociatePublicIpAddress *bool                        `json:"AssociatePublicIpAddress,omitempty"`
	BlockDeviceMappings      []*cloudformationBlockDevice `json:"BlockDeviceMappings,omitempty"`
	EBSOptimized             *bool                        `json:"EbsOptimized,omitempty"`
	IAMInstanceProfile       *cloudformation.Literal      `json:"IamInstanceProfile,omitempty"`
	ImageID                  *string                      `json:"ImageId,omitempty"`
	InstanceType             *string                      `json:"InstanceType,omitempty"`
	KeyName                  *string                      `json:"KeyName,omitempty"`
	SecurityGroups           []*cloudformation.Literal    `json:"SecurityGroups,omitempty"`
	SpotPrice                *string                      `json:"SpotPrice,omitempty"`
	UserData                 *string                      `json:"UserData,omitempty"`
	PlacementTenancy         *string                      `json:"PlacementTenancy,omitempty"`
	InstanceMonitoring       *bool                        `json:"InstanceMonitoring,omitempty"`

	//NamePrefix               *string                 `json:"name_prefix,omitempty"`
	//Lifecycle                *cloudformation.Lifecycle    `json:"lifecycle,omitempty"`
}

type cloudformationBlockDevice struct {
	// For ephemeral devices
	DeviceName  *string `json:"DeviceName,omitempty"`
	VirtualName *string `json:"VirtualName,omitempty"`

	// For root
	Ebs *cloudformationBlockDeviceEBS `json:"Ebs,omitempty"`
}

type cloudformationBlockDeviceEBS struct {
	VolumeType          *string `json:"VolumeType,omitempty"`
	VolumeSize          *int64  `json:"VolumeSize,omitempty"`
	DeleteOnTermination *bool   `json:"DeleteOnTermination,omitempty"`
}

func (_ *LaunchTemplate) RenderCloudformation(t *cloudformation.CloudformationTarget, a, e, changes *LaunchConfiguration) error {
	cloud := t.Cloud.(awsup.AWSCloud)

	if e.ImageID == nil {
		return fi.RequiredField("ImageID")
	}
	image, err := cloud.ResolveImage(*e.ImageID)
	if err != nil {
		return err
	}

	cf := &cloudformationLaunchTemplate{
		//NamePrefix:   fi.String(*e.Name + "-"),
		ImageID:      image.ImageId,
		InstanceType: e.InstanceType,
	}

	if e.SpotPrice != "" {
		cf.SpotPrice = aws.String(e.SpotPrice)
	}

	if e.SSHKey != nil {
		if e.SSHKey.Name == nil {
			return fmt.Errorf("SSHKey Name not set")
		}
		cf.KeyName = e.SSHKey.Name
	}

	if e.Tenancy != nil {
		cf.PlacementTenancy = e.Tenancy
	}

	for _, sg := range e.SecurityGroups {
		cf.SecurityGroups = append(cf.SecurityGroups, sg.CloudformationLink())
	}
	cf.AssociatePublicIpAddress = e.AssociatePublicIP

	cf.EBSOptimized = e.RootVolumeOptimization

	{
		rootDevices, err := e.buildRootDevice(cloud)
		if err != nil {
			return err
		}

		ephemeralDevices, err := buildEphemeralDevices(e.InstanceType)
		if err != nil {
			return err
		}

		if len(rootDevices) != 0 {
			if len(rootDevices) != 1 {
				return fmt.Errorf("unexpectedly found multiple root devices")
			}

			for deviceName, bdm := range rootDevices {
				d := &cloudformationBlockDevice{
					DeviceName: fi.String(deviceName),
					Ebs: &cloudformationBlockDeviceEBS{
						VolumeType:          bdm.EbsVolumeType,
						VolumeSize:          bdm.EbsVolumeSize,
						DeleteOnTermination: fi.Bool(true),
					},
				}
				cf.BlockDeviceMappings = append(cf.BlockDeviceMappings, d)
			}
		}

		if len(ephemeralDevices) != 0 {
			for deviceName, bdm := range ephemeralDevices {
				cf.BlockDeviceMappings = append(cf.BlockDeviceMappings, &cloudformationBlockDevice{
					VirtualName: bdm.VirtualName,
					DeviceName:  fi.String(deviceName),
				})
			}
		}
	}

	if e.UserData != nil {
		d, err := e.UserData.AsBytes()
		if err != nil {
			return fmt.Errorf("error rendering AutoScalingLaunchTemplate UserData: %v", err)
		}
		cf.UserData = aws.String(base64.StdEncoding.EncodeToString(d))
	}

	if e.IAMInstanceProfile != nil {
		cf.IAMInstanceProfile = e.IAMInstanceProfile.CloudformationLink()
	}

	if e.InstanceMonitoring != nil {
		cf.InstanceMonitoring = e.InstanceMonitoring
	} else {
		cf.InstanceMonitoring = fi.Bool(false)
	}
	// So that we can update configurations
	//tf.Lifecycle = &cloudformation.Lifecycle{CreateBeforeDestroy: fi.Bool(true)}

	return t.RenderResource("AWS::AutoScaling::LaunchTemplate", *e.Name, cf)
}

func (e *LaunchTemplate) CloudformationLink() *cloudformation.Literal {
	return cloudformation.Ref("AWS::AutoScaling::LaunchTemplate", *e.Name)
}

// deleteLaunchTemplate tracks a LaunchConfiguration that we're going to delete
// It implements fi.Deletion
type deleteLaunchTemplate struct {
	lc *autoscaling.LaunchTemplate
}

var _ fi.Deletion = &deleteLaunchTemplate{}

func (d *deleteLaunchTemplate) TaskName() string {
	return "LaunchTemplate"
}

func (d *deleteLaunchTemplate) Item() string {
	return aws.StringValue(d.lc.LaunchTemplateName)
}

func (d *deleteLaunchTemplate) Delete(t fi.Target) error {
	glog.V(2).Infof("deleting launch configuration %v", d)

	awsTarget, ok := t.(*awsup.AWSAPITarget)
	if !ok {
		return fmt.Errorf("unexpected target type for deletion: %T", t)
	}

	request := &autoscaling.DeleteLaunchTemplateInput{
		LaunchTemplateName: d.lc.LaunchConfigurationName,
	}

	name := aws.StringValue(request.LaunchTemplateName)
	glog.V(2).Infof("Calling autoscaling DeleteLaunchTemplate for %s", name)
	_, err := awsTarget.Cloud.Autoscaling().DeleteLaunchTemplate(request)
	if err != nil {
		return fmt.Errorf("error deleting autoscaling LaunchTemplate %s: %v", name, err)
	}

	return nil
}

func (d *deleteLaunchTemplate) String() string {
	return d.TaskName() + "-" + d.Item()
}

func (e *LaunchTemplate) FindDeletions(c *fi.Context) ([]fi.Deletion, error) {
	var removals []fi.Deletion

	configurations, err := e.findLaunchTemplates(c)
	if err != nil {
		return nil, err
	}

	if len(configurations) <= RetainLaunchTemplateCount() {
		return nil, nil
	}

	configurations = configurations[:len(configurations)-RetainLaunchTemplateCount()]

	for _, configuration := range configurations {
		removals = append(removals, &deleteLaunchTemplate{lc: configuration})
	}

	glog.V(2).Infof("will delete launch configurations: %v", removals)

	return removals, nil
}
