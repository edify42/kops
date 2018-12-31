/*
Copyright 2018 The Kubernetes Authors.

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
	"testing"

	"k8s.io/kops/upup/pkg/fi"
)

func TestLaunchTemplateTerraformRender(t *testing.T) {
	cases := []*terraformTest{
		{
			Resource: &LaunchTemplate{
				Name:              fi.String("test"),
				AssociatePublicIP: fi.Bool(true),
				IAMInstanceProfile: &IAMInstanceProfile{
					Name: fi.String("nodes"),
				},
				ID:                     fi.String("test-11"),
				InstanceMonitoring:     fi.Bool(true),
				InstanceType:           fi.String("t2.medium"),
				RootVolumeOptimization: fi.Bool(true),
				RootVolumeIops:         fi.Int64(100),
				RootVolumeSize:         fi.Int64(64),
				SSHKey: &SSHKey{
					Name: fi.String("mykey"),
				},
				SecurityGroups: []*SecurityGroup{
					{Name: fi.String("nodes-1"), ID: fi.String("1111")},
					{Name: fi.String("nodes-2"), ID: fi.String("2222")},
				},
				Tenancy: fi.String("dedicated"),
			},
			Expected: `provider "aws" {
  region = "eu-west-2"
}

resource "aws_launch_template" "test" {
  name_prefix = "test-"

  lifecycle = {
    create_before_destroy = true
  }

  ebs_optimized = true

  iam_instance_profile = {
    name = "${aws_iam_instance_profile.nodes.id}"
  }

  instance_type = "t2.medium"
  key_name      = "${aws_key_pair.mykey.id}"

  network_interfaces = {
    associate_public_ip_address = true
  }

  placement = {
    tenancy = "dedicated"
  }

  vpc_security_group_ids = ["${aws_security_group.nodes-1.id}", "${aws_security_group.nodes-2.id}"]
}

terraform = {
  required_version = ">= 0.9.3"
}
`,
		},
	}
	doTerraformRenderTests(t, cases)
}
