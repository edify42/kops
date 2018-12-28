/*
Copyright 2017 The Kubernetes Authors.

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

package validation

import (
	"fmt"
	"regexp"

	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/kops/pkg/apis/kops"
	"k8s.io/kops/pkg/apis/kops/util"
	"k8s.io/kops/upup/pkg/fi"
	"k8s.io/kops/util/pkg/slice"
)

// ValidateInstanceGroup is responsible for validating the configuration of a instancegroup
func ValidateInstanceGroup(g *kops.InstanceGroup) error {
	if g.ObjectMeta.Name == "" {
		return field.Required(field.NewPath("Name"), "")
	}

	switch g.Spec.Role {
	case "":
		return field.Required(field.NewPath("Role"), "Role must be set")
	case kops.InstanceGroupRoleMaster:
	case kops.InstanceGroupRoleNode:
	case kops.InstanceGroupRoleBastion:
	default:
		return field.Invalid(field.NewPath("Role"), g.Spec.Role, "Unknown role")
	}

	if g.Spec.Tenancy != "" {
		if g.Spec.Tenancy != "default" && g.Spec.Tenancy != "dedicated" && g.Spec.Tenancy != "host" {
			return field.Invalid(field.NewPath("Tenancy"), g.Spec.Tenancy, "Unknown tenancy. Must be Default, Dedicated or Host.")
		}
	}

	if g.Spec.MaxSize != nil && g.Spec.MinSize != nil {
		if *g.Spec.MaxSize < *g.Spec.MinSize {
			return field.Invalid(field.NewPath("MaxSize"), *g.Spec.MaxSize, "maxSize must be greater than or equal to minSize.")
		}
	}

	if fi.Int32Value(g.Spec.RootVolumeIops) < 0 {
		return field.Invalid(field.NewPath("RootVolumeIops"), g.Spec.RootVolumeIops, "RootVolumeIops must be greater than 0")
	}

	// @check all the hooks are valid in this instancegroup
	for i := range g.Spec.Hooks {
		if errs := validateHookSpec(&g.Spec.Hooks[i], field.NewPath("hooks").Index(i)); len(errs) > 0 {
			return errs.ToAggregate()
		}
	}

	// @check the fileAssets for this instancegroup are valid
	for i := range g.Spec.FileAssets {
		if errs := validateFileAssetSpec(&g.Spec.FileAssets[i], field.NewPath("fileAssets").Index(i)); len(errs) > 0 {
			return errs.ToAggregate()
		}
	}

	if g.IsMaster() {
		if len(g.Spec.Subnets) == 0 {
			return fmt.Errorf("Master InstanceGroup %s did not specify any Subnets", g.ObjectMeta.Name)
		}
	}

	if g.Spec.MixedInstancesPolicy != nil {
		if errs := validatedMixedInstancesPolicy(field.NewPath(g.Name), g.Spec.MixedInstancesPolicy, g); len(errs) > 0 {
			return errs.ToAggregate()
		}
	}

	if len(g.Spec.AdditionalUserData) > 0 {
		for _, UserDataInfo := range g.Spec.AdditionalUserData {
			err := validateExtraUserData(&UserDataInfo)
			if err != nil {
				return err
			}
		}
	}

	if err := validateInstanceProfile(g.Spec.IAM, field.NewPath("iam")); err != nil {
		return err
	}

	return nil
}

// validatedMixedInstancesPolicy is responsible for validating the user input of a mixed instance policy
func validatedMixedInstancesPolicy(path *field.Path, spec *kops.MixedInstancesPolicySpec, ig *kops.InstanceGroup) field.ErrorList {
	var errs field.ErrorList

	if len(spec.Instances) < 2 {
		errs = append(errs, field.Invalid(path.Child("instances"), spec.Instances, "must be 2 or more instance types"))
	}
	// @step: check the instances are validate
	for i, x := range spec.Instances {
		errs = append(errs, awsValidateMachineType(path.Child("instances").Index(i).Child("instanceType"), x)...)
	}

	if spec.OnDemandBase != nil {
		if fi.Int64Value(spec.OnDemandBase) < 0 {
			errs = append(errs, field.Invalid(path.Child("onDemandBase"), spec.OnDemandBase, "cannot be less than zero"))
		}
		if fi.Int64Value(spec.OnDemandBase) > int64(fi.Int32Value(ig.Spec.MaxSize)) {
			errs = append(errs, field.Invalid(path.Child("onDemandBase"), spec.OnDemandBase, "cannot be greater than max size"))
		}
	}

	if spec.OnDemandAboveBase != nil {
		if fi.Int64Value(spec.OnDemandAboveBase) < 0 {
			errs = append(errs, field.Invalid(path.Child("onDemandAboveBase"), spec.OnDemandAboveBase, "cannout be less then zero"))
		}
	}

	if spec.SpotAllocationStrategy != nil && !slice.Contains(kops.SpotAllocationStrategies, fi.StringValue(spec.SpotAllocationStrategy)) {
		errs = append(errs, field.Invalid(path.Child("spotAllocationStrategy"), spec.SpotAllocationStrategy, "unsupport spot allocation stratergy"))
	}

	return errs
}

// CrossValidateInstanceGroup performs validation of the instance group, including that it is consistent with the Cluster
// It calls ValidateInstanceGroup, so all that validation is included.
func CrossValidateInstanceGroup(g *kops.InstanceGroup, cluster *kops.Cluster, strict bool) error {
	err := ValidateInstanceGroup(g)
	if err != nil {
		return err
	}

	// Check that instance groups are defined in subnets that are defined in the cluster
	{
		clusterSubnets := make(map[string]*kops.ClusterSubnetSpec)
		for i := range cluster.Spec.Subnets {
			s := &cluster.Spec.Subnets[i]
			if clusterSubnets[s.Name] != nil {
				return fmt.Errorf("Subnets contained a duplicate value: %v", s.Name)
			}
			clusterSubnets[s.Name] = s
		}

		for _, z := range g.Spec.Subnets {
			if clusterSubnets[z] == nil {
				return fmt.Errorf("InstanceGroup %q is configured in %q, but this is not configured as a Subnet in the cluster", g.ObjectMeta.Name, z)
			}
		}
	}

	k8sVersion, err := util.ParseKubernetesVersion(cluster.Spec.KubernetesVersion)
	if err != nil {
		return fmt.Errorf("Unable to determine kubernetes version from %q", cluster.Spec.KubernetesVersion)
	}

	allErrs := field.ErrorList{}
	fieldPath := field.NewPath("InstanceGroup")

	if k8sVersion.Major == 1 && k8sVersion.Minor <= 5 {
		if len(g.Spec.Taints) > 0 {
			if !(g.IsMaster() && g.Spec.Taints[0] == kops.TaintNoScheduleMaster15 && len(g.Spec.Taints) == 1) {
				allErrs = append(allErrs, field.Invalid(fieldPath.Child("Spec").Child("Taints"), g.Spec.Taints, "User-specified taints are not supported before kubernetes version 1.6.0"))
			}
		}
	}

	if len(allErrs) != 0 {
		return allErrs[0]
	}

	return nil
}

func validateExtraUserData(userData *kops.UserData) error {
	fieldPath := field.NewPath("AdditionalUserData")

	if userData.Name == "" {
		return field.Required(fieldPath.Child("Name"), "field must be set")
	}

	if userData.Content == "" {
		return field.Required(fieldPath.Child("Content"), "field must be set")
	}

	switch userData.Type {
	case "text/x-include-once-url":
	case "text/x-include-url":
	case "text/cloud-config-archive":
	case "text/upstart-job":
	case "text/cloud-config":
	case "text/part-handler":
	case "text/x-shellscript":
	case "text/cloud-boothook":

	default:
		return field.Invalid(fieldPath.Child("Type"), userData.Type, "Invalid user-data content type")
	}

	return nil
}

// format is arn:aws:iam::123456789012:instance-profile/S3Access
var validARN = regexp.MustCompile(`^arn:aws:iam::\d+:instance-profile\/\S+$`)

// validateInstanceProfile checks the String values for the AuthProfile
func validateInstanceProfile(v *kops.IAMProfileSpec, fldPath *field.Path) *field.Error {
	if v != nil && v.Profile != nil {
		arn := *v.Profile
		if !validARN.MatchString(arn) {
			return field.Invalid(fldPath.Child("Profile"), arn,
				"Instance Group IAM Instance Profile must be a valid aws arn such as arn:aws:iam::123456789012:instance-profile/KopsExampleRole")
		}
	}
	return nil
}
