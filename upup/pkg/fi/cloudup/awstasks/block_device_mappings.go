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
	"k8s.io/kops/upup/pkg/fi"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/autoscaling"
	"github.com/aws/aws-sdk-go/service/ec2"
)

// BlockDeviceMapping represents a device mapping
type BlockDeviceMapping struct {
	EbsDeleteOnTermination *bool
	EbsVolumeIops          *int64
	EbsVolumeSize          *int64
	EbsVolumeType          *string
	VirtualName            *string
}

// BlockDeviceMappingFromEC2 returns a block device from a ec2 block device mapping
func BlockDeviceMappingFromEC2(i *ec2.BlockDeviceMapping) (string, *BlockDeviceMapping) {
	o := &BlockDeviceMapping{}
	o.VirtualName = i.VirtualName
	if i.Ebs != nil {
		o.EbsDeleteOnTermination = i.Ebs.DeleteOnTermination
		o.EbsVolumeSize = i.Ebs.VolumeSize
		o.EbsVolumeType = i.Ebs.VolumeType
	}
	return aws.StringValue(i.DeviceName), o
}

// ToEC2 converts the device block mapping to a ec2 definition
func (i *BlockDeviceMapping) ToEC2(deviceName string) *ec2.BlockDeviceMapping {
	o := &ec2.BlockDeviceMapping{}
	o.DeviceName = aws.String(deviceName)
	o.VirtualName = i.VirtualName
	if i.EbsDeleteOnTermination != nil || i.EbsVolumeSize != nil || i.EbsVolumeType != nil {
		o.Ebs = &ec2.EbsBlockDevice{}
		o.Ebs.DeleteOnTermination = i.EbsDeleteOnTermination
		o.Ebs.VolumeSize = i.EbsVolumeSize
		o.Ebs.VolumeType = i.EbsVolumeType
	}
	return o
}

func BlockDeviceMappingFromAutoscaling(i *autoscaling.BlockDeviceMapping) (string, *BlockDeviceMapping) {
	o := &BlockDeviceMapping{}
	o.VirtualName = i.VirtualName
	if i.Ebs != nil {
		o.EbsDeleteOnTermination = i.Ebs.DeleteOnTermination
		o.EbsVolumeSize = i.Ebs.VolumeSize
		o.EbsVolumeType = i.Ebs.VolumeType
	}

	return aws.StringValue(i.DeviceName), o
}

func (i *BlockDeviceMapping) ToAutoscaling(deviceName string) *autoscaling.BlockDeviceMapping {
	o := &autoscaling.BlockDeviceMapping{}
	o.DeviceName = aws.String(deviceName)
	o.VirtualName = i.VirtualName

	if i.EbsDeleteOnTermination != nil || i.EbsVolumeSize != nil || i.EbsVolumeType != nil {
		o.Ebs = &autoscaling.Ebs{}
		o.Ebs.DeleteOnTermination = i.EbsDeleteOnTermination
		o.Ebs.VolumeSize = i.EbsVolumeSize
		o.Ebs.VolumeType = i.EbsVolumeType
		o.Ebs.Iops = i.EbsVolumeIops
	}

	return o
}

// BlockDeviceMappingFromLaunchTemplateBootDeviceRequest coverts the launch template device mappings to an interval block device mapping
func BlockDeviceMappingFromLaunchTemplateBootDeviceRequest(i *ec2.LaunchTemplateBlockDeviceMappingRequest) (string, *BlockDeviceMapping) {
	o := &BlockDeviceMapping{}
	o.VirtualName = i.VirtualName
	if i.Ebs != nil {
		o.EbsDeleteOnTermination = i.Ebs.DeleteOnTermination
		o.EbsVolumeSize = i.Ebs.VolumeSize
		o.EbsVolumeType = i.Ebs.VolumeType
	}

	return aws.StringValue(i.DeviceName), o
}

// ToLaunchTemplateBootDeviceRequest coverts in the internal block device mapping to a launcg template request
func (i *BlockDeviceMapping) ToLaunchTemplateBootDeviceRequest(deviceName string) *ec2.LaunchTemplateBlockDeviceMappingRequest {
	o := &ec2.LaunchTemplateBlockDeviceMappingRequest{}
	o.DeviceName = aws.String(deviceName)
	o.VirtualName = i.VirtualName
	if i.EbsDeleteOnTermination != nil || i.EbsVolumeSize != nil || i.EbsVolumeType != nil || i.EbsVolumeIops != nil {
		o.Ebs = &ec2.LaunchTemplateEbsBlockDeviceRequest{
			DeleteOnTermination: i.EbsDeleteOnTermination,
			VolumeSize:          i.EbsVolumeSize,
			VolumeType:          i.EbsVolumeType,
			Iops:                i.EbsVolumeIops,
		}
	}

	return o
}

var _ fi.HasDependencies = &BlockDeviceMapping{}

func (f *BlockDeviceMapping) GetDependencies(tasks map[string]fi.Task) []fi.Task {
	return nil
}
