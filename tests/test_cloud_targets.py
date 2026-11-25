"""cloud_account rules: what cloud account a command names (catpilot_guard/cloud_targets.py), and the company-rules
hook's decision on it (docs/spec/OVERLAY_V2.md §2.2: an allow-list, so an account no value covers fires the rule)."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from catpilot_guard import company_rules as cr  # noqa: E402
from catpilot_guard import policy as pol  # noqa: E402
from catpilot_guard.cloud_targets import ACCOUNT, UNKNOWN, Target, account_covered, cloud_targets  # noqa: E402

HOOK = ROOT / "hooks" / "claude-code" / "pretooluse-company-rules.py"
# Planted in commands and in a rule's values; none may reach a reason or an evidence line.
MARKER_AWS = "730194628517"
MARKER_GCP = "zq-marker-project"
MARKER_AZURE = "c4a7e1d2-9b3f-4e8a-b6c5-2d1f0e9a8b7c"
GUID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"


def targets(command):
    return [(t.kind, t.name) for t in cloud_targets(command)]


class CloudTargetTests(unittest.TestCase):
    def test_commands_that_name_an_account(self):
        cases = {
            # AWS: an ARN's account in any argument of aws, sam or cdk, and the account-id options.
            "aws sts assume-role --role-arn arn:aws:iam::123456789012:role/x --role-session-name s": "aws:123456789012",
            "aws lambda invoke --function-name arn:aws:lambda:us-east-1:123456789012:function:f out.json": "aws:123456789012",
            "aws lambda get-function --function-name arn:aws-us-gov:lambda:us-gov-west-1:123456789012:function:f": "aws:123456789012",
            "aws s3 ls --region cn-north-1 --profile x arn:aws-cn:s3:cn-north-1:123456789012:accesspoint/a": "aws:123456789012",
            "aws s3api put-bucket-policy --bucket b --policy '{\"Principal\":{\"AWS\":\"arn:aws:iam::123456789012:root\"},"
            "\"Resource\":\"arn:aws:s3:::b/*\"}'": "aws:123456789012",
            "aws organizations describe-account --account-id 123456789012": "aws:123456789012",
            "aws s3control list-jobs --account-id=123456789012": "aws:123456789012",
            "aws quicksight list-users --aws-account-id 123456789012 --namespace default": "aws:123456789012",
            "aws lambda add-permission --function-name f --source-account 123456789012 --action x": "aws:123456789012",
            "aws configure set sso_account_id 123456789012": "aws:123456789012",
            "aws configure set profile.dev.sso_account_id 123456789012 --profile dev": "aws:123456789012",
            "aws configure set role_arn arn:aws:iam::123456789012:role/admin": "aws:123456789012",
            "sam deploy --role-arn arn:aws:iam::123456789012:role/deployer": "aws:123456789012",
            "cdk bootstrap aws://123456789012/us-east-1": "aws:123456789012",
            "npx aws-cdk deploy --role-arn arn:aws:iam::123456789012:role/d": "aws:123456789012",
            "npx aws-cdk@2 bootstrap aws://123456789012/eu-west-1": "aws:123456789012",
            "AWS_ROLE_ARN=arn:aws:iam::123456789012:role/ci aws s3 ls": "aws:123456789012",
            # GCP.
            "gcloud run deploy svc --project acme-prod-1": "gcp:acme-prod-1",
            "gcloud --project=acme-prod-1 compute instances list": "gcp:acme-prod-1",
            "gcloud storage ls --billing-project acme-billing": "gcp:acme-billing",
            "gcloud config set project acme-prod-1": "gcp:acme-prod-1",
            "gcloud config set core/project Acme-Prod-1": "gcp:acme-prod-1",
            "gcloud projects describe acme-prod-1": "gcp:acme-prod-1",
            "gcloud projects create acme-new-1 --name 'New one'": "gcp:acme-new-1",
            "gcloud beta projects add-iam-policy-binding acme-prod-1 --member=user:a@example.org --role=roles/viewer": "gcp:acme-prod-1",
            "gsutil -u acme-billing cp gs://a/b .": "gcp:acme-billing",
            "gsutil -m -u acme-billing ls gs://a": "gcp:acme-billing",
            "gsutil -mu acme-billing ls gs://a": "gcp:acme-billing",
            "bq --project_id=acme-data query 'select 1'": "gcp:acme-data",
            "bq --project_id acme-data ls": "gcp:acme-data",
            "CLOUDSDK_CORE_PROJECT=acme-dev-1 gcloud app deploy": "gcp:acme-dev-1",
            "GOOGLE_CLOUD_PROJECT=acme-dev-1 python deploy.py": "gcp:acme-dev-1",
            "export CLOUDSDK_CORE_PROJECT=acme-dev-1": "gcp:acme-dev-1",
            # Azure.
            "az vm list --subscription %s" % GUID: "azure:" + GUID,
            "az vm list --subscription=%s" % GUID.upper(): "azure:" + GUID,
            "az account set -s %s" % GUID: "azure:" + GUID,
            "az account set --name %s" % GUID: "azure:" + GUID,
            "az role assignment create --scope /subscriptions/%s/resourceGroups/rg --role Reader --assignee x" % GUID: "azure:" + GUID,
            "az rest --method get --url https://management.azure.com/subscriptions/%s/resourcegroups?api-version=2021-04-01" % GUID: "azure:" + GUID,
            "AZURE_SUBSCRIPTION_ID=%s terraform apply" % GUID: "azure:" + GUID,
            "env ARM_SUBSCRIPTION_ID=%s terraform plan" % GUID: "azure:" + GUID,
            # Through the same splitting and wrappers as the other checks.
            "sudo -E aws sts assume-role --role-arn arn:aws:iam::123456789012:role/x --role-session-name s": "aws:123456789012",
            "bash -lc 'gcloud config set project acme-prod-1'": "gcp:acme-prod-1",
            "cd infra && az account set -s %s" % GUID: "azure:" + GUID,
            "npx -c 'aws organizations describe-account --account-id 123456789012'": "aws:123456789012",
        }
        for command, name in cases.items():
            with self.subTest(command=command):
                self.assertEqual(targets(command), [(ACCOUNT, name)])

    def test_several_accounts_in_one_command(self):
        self.assertEqual(targets("aws securityhub invite-members --account-ids 111111111111 222222222222 --region us-east-1"),
                         [(ACCOUNT, "aws:111111111111"), (ACCOUNT, "aws:222222222222")])
        self.assertEqual(targets("aws iam put-role-policy --policy-document "
                                 "'{\"Resource\":[\"arn:aws:iam::111111111111:role/a\",\"arn:aws:iam::222222222222:role/b\"]}'"),
                         [(ACCOUNT, "aws:111111111111"), (ACCOUNT, "aws:222222222222")])
        self.assertEqual(targets("gcloud config set project acme-a-1 && az account set -s %s" % GUID),
                         [(ACCOUNT, "gcp:acme-a-1"), (ACCOUNT, "azure:" + GUID)])

    def test_accounts_the_hook_cannot_read_are_unknown(self):
        for command in ("aws sts assume-role --role-arn $ROLE --role-session-name s",
                        "aws sts assume-role --role-arn \"$(terraform output -raw role)\" --role-session-name s",
                        "aws s3control list-jobs --account-id $ACCOUNT", "aws organizations describe-account --account-id 1234",
                        "aws sts assume-role --role-arn arn:aws:iam::$ACCOUNT_ID:role/x --role-session-name s",
                        "gcloud run deploy --project $PROJECT", "gcloud projects describe 123456789012",
                        "gcloud config set project ${P}", "gcloud --project=a compute instances list", "gsutil -u $P ls",
                        "bq --project_id=$P ls", "az account set -s 'My Subscription'", "az vm list --subscription Production",
                        "az group list --subscription $SUB", "az resource show --ids /subscriptions/$SUB/resourceGroups/rg",
                        "AZURE_SUBSCRIPTION_ID=$SUB terraform apply", "CLOUDSDK_CORE_PROJECT=$P gcloud app deploy",
                        "cdk bootstrap aws://$ACCOUNT/us-east-1"):
            with self.subTest(command=command):
                self.assertIn((UNKNOWN, None), targets(command))
                self.assertFalse([t for t in targets(command) if t[0] == ACCOUNT])

    def test_commands_that_name_no_account(self):
        for command in ("aws s3 ls", "aws --profile prod s3 ls", "AWS_PROFILE=prod aws s3 ls", "aws sts get-caller-identity",
                        "aws iam get-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
                        "aws s3api get-bucket-policy --bucket arn:aws:s3:::bucket", "aws glacier list-vaults --account-id -",
                        "aws iam create-policy --policy-document '{\"Resource\":\"arn:aws:iam::*:role/x\"}'",
                        "aws ec2 describe-instances --max-items 123456789012", "cdk deploy", "cdk bootstrap aws://unknown-account/us-east-1",
                        "sam deploy", "gcloud run deploy", "gcloud projects list", "gcloud config set account a@example.org",
                        "gcloud config configurations activate prod", "gcloud --configuration prod compute instances list",
                        "gsutil -m rsync -u -r src gs://bucket", "gsutil ls gs://acme-prod-1-bucket", "bq ls",
                        "az group list", "az login", "az account show", "terraform apply", "pulumi up",
                        "echo arn:aws:iam::123456789012:role/x", "terraform import aws_iam_role.r arn:aws:iam::123456789012:role/x",
                        "kubectl --context arn:aws:eks:us-east-1:123456789012:cluster/c get pods", "FOO=123456789012 ls", "ls"):
            with self.subTest(command=command):
                self.assertEqual(targets(command), [])

    def test_an_arn_with_a_variable_it_cannot_read_around_is_unknown(self):
        # Review of PR #135: a command substitution with a space in the account field, and a variable partition, gave
        # no target at all.
        for command in ('aws iam attach-role-policy --role-name r --policy-arn "arn:aws:iam::$(cat other):policy/x"',
                        'aws iam attach-role-policy --role-name r --policy-arn "arn:aws:iam::`cat other`:policy/x"',
                        'aws iam attach-role-policy --role-name r --policy-arn "arn:${PARTITION}:iam::111122223333:policy/x"',
                        'aws iam attach-role-policy --role-name r --policy-arn "arn:$P:iam::111122223333:policy/x"',
                        'aws iam attach-role-policy --role-name r --policy-arn "arn:`echo aws`:iam::111122223333:policy/x"',
                        'aws lambda invoke --function-name "arn:aws:lambda:$(aws configure get region):999988887777:function:f" o',
                        'aws lambda invoke --function-name "arn:aws:lambda:${R:-us}:999988887777:function:f" o',
                        "AWS_ROLE_ARN='arn:aws:iam::$(cat id):role/ci' aws s3 ls"):
            with self.subTest(command=command):
                self.assertEqual(targets(command), [(UNKNOWN, None)])
        # A variable region before a literal account still names the account; an S3 ARN has no account.
        self.assertEqual(targets('aws lambda invoke --function-name "arn:aws:lambda:${AWS_REGION}:123456789012:function:f" o'),
                         [(ACCOUNT, "aws:123456789012")])
        self.assertEqual(targets('aws s3api get-object --bucket b --key "arn:aws:s3:::${BUCKET}/k" out'), [])

    def test_abbreviated_account_options(self):
        # The AWS CLI and az parse with argparse, which takes a unique prefix of a long option.
        cases = {
            "aws organizations describe-account --account-i 999988887777": "aws:999988887777",
            "aws organizations describe-account --acc=999988887777": "aws:999988887777",
            "aws quicksight list-users --aws 999988887777 --namespace default": "aws:999988887777",
            "aws quicksight list-users --aws-account-i=999988887777 --namespace default": "aws:999988887777",
            "aws lambda add-permission --function-name f --source-ac 999988887777 --action x": "aws:999988887777",
            "aws securityhub invite-members --account-id 999988887777": "aws:999988887777",
            "az vm list --subs %s" % GUID: "azure:" + GUID,
            "az vm list --sub=%s" % GUID: "azure:" + GUID,
            "az account set --na %s" % GUID: "azure:" + GUID,
            "az account set --n %s" % GUID: "azure:" + GUID,
            "az account alias create --name x --subscription-id %s" % GUID: "azure:" + GUID,
            "bq -project_id acme-data ls": "gcp:acme-data",
        }
        for command, name in cases.items():
            with self.subTest(command=command):
                self.assertEqual(targets(command), [(ACCOUNT, name)])
        self.assertEqual(targets("aws sts assume-role --role-a $ROLE --role-session-name s"), [(UNKNOWN, None)])
        self.assertEqual(targets("az graph query -q x --subscriptions %s %s" % (GUID, GUID.replace("a", "b"))),
                         [(ACCOUNT, "azure:" + GUID), (ACCOUNT, "azure:" + GUID.replace("a", "b"))])
        # Another command's own option that a shorter prefix would match, and options that only share a prefix.
        for command in ("aws codebuild create-project --source '{\"type\":\"S3\"}' --name x",
                        "aws lambda create-function --role-name x --function-name f", "aws glacier list-vaults --account -",
                        "aws ec2 describe-instances --accept x", "az network vnet subnet create --subnet x -n y",
                        "az account set --no-wait"):
            with self.subTest(command=command):
                self.assertEqual(targets(command), [])

    def test_gsutil_project_options_and_role_arn_settings(self):
        for command in ("gsutil mb -p acme-other-1 gs://bucket", "gsutil -m mb -l us -p acme-other-1 gs://bucket",
                        "gsutil ls -p acme-other-1", "gsutil ls -lp acme-other-1", "gsutil hmac create -p acme-other-1 sa@x.example",
                        "gsutil kms authorize -p acme-other-1 -k key"):
            with self.subTest(command=command):
                self.assertEqual(targets(command), [(ACCOUNT, "gcp:acme-other-1")])
        self.assertEqual(targets("gsutil notification create -f json -p prefix gs://b"), [])  # -p is an object prefix there
        self.assertEqual(targets('aws configure set role_arn "$ROLE"'), [(UNKNOWN, None)])
        self.assertEqual(targets("aws configure set profile.dev.role_arn arn:aws:iam::999988887777:role/x"),
                         [(ACCOUNT, "aws:999988887777")])

    def test_runners_are_looked_through_as_the_registry_reader_does(self):
        for command in ("uv run aws sts assume-role --role-arn arn:aws:iam::999988887777:role/x --role-session-name s",
                        "uv run --no-project -- aws sts assume-role --role-arn arn:aws:iam::999988887777:role/x",
                        "poetry run aws sts assume-role --role-arn arn:aws:iam::999988887777:role/x",
                        "pipenv run aws sts assume-role --role-arn arn:aws:iam::999988887777:role/x",
                        "uvx --from awscli aws sts assume-role --role-arn arn:aws:iam::999988887777:role/x",
                        "uv tool run --from awscli aws sts assume-role --role-arn arn:aws:iam::999988887777:role/x",
                        "python -m awscli sts assume-role --role-arn arn:aws:iam::999988887777:role/x",
                        "bundle exec aws sts assume-role --role-arn arn:aws:iam::999988887777:role/x"):
            with self.subTest(command=command):
                self.assertEqual(targets(command), [(ACCOUNT, "aws:999988887777")])
        self.assertEqual(targets("poetry -C infra run gcloud config set project acme-other-1"), [(ACCOUNT, "gcp:acme-other-1")])

    def test_an_account_option_left_last_is_unknown(self):
        # xargs or stdin supplies the value, which the hook cannot read.
        for command in ("echo x | xargs gcloud run deploy --project", "echo x | xargs az vm list --subscription",
                        "echo x | xargs aws organizations describe-account --account-id",
                        "echo x | xargs aws securityhub invite-members --account-ids",
                        "echo x | xargs aws sts assume-role --role-session-name s --role-arn", "echo x | xargs bq ls --project_id",
                        "echo x | xargs gcloud config set project", "echo x | xargs gcloud projects describe",
                        "echo x | xargs gsutil -u", "echo x | xargs gsutil mb -p", "echo x | xargs az account set -s",
                        "echo x | xargs aws configure set sso_account_id", "echo x | xargs aws configure set role_arn"):
            with self.subTest(command=command):
                self.assertEqual(targets(command), [(UNKNOWN, None)])
        self.assertEqual(targets("gcloud projects describe --help"), [])

    # Second review of PR #135 (564d238).

    def test_shorter_abbreviations_read_only_account_shaped_values(self):
        cases = {
            "aws organizations describe-account --ac 999988887777": "aws:999988887777",
            "aws organizations describe-account --a 999988887777": "aws:999988887777",
            "aws quicksight list-users --aw 999988887777 --namespace default": "aws:999988887777",
            "aws quicksight list-users --a=999988887777 --namespace default": "aws:999988887777",
            "aws lambda add-permission --function-name f --sou 999988887777 --action x": "aws:999988887777",
            "az group list --su %s" % GUID: "azure:" + GUID,
            "az group list --s %s" % GUID.upper(): "azure:" + GUID,
        }
        for command, name in cases.items():
            with self.subTest(command=command):
                self.assertEqual(targets(command), [(ACCOUNT, name)])
        # On aws, another option's abbreviation with a literal value that is not an account names nothing.
        for command in ("aws s3api put-object --bucket b --key k --ac private", "aws ec2 run-instances --a ami-123",
                        "aws lambda add-permission --function-name f --sou s3 --action x"):
            with self.subTest(command=command):
                self.assertEqual(targets(command), [])
        # A variable or a missing value is unknown, as for the long forms; az's --subscription is a global argument of
        # nearly every command, so --s and --su are read as it, a name included.
        for command in ("aws quicksight list-users --aw $ACCT --namespace default", "aws organizations describe-account --a `cat id`",
                        "echo x | xargs aws organizations describe-account --ac", "az group list --s MySubName",
                        "az group list --s $SUB", "az vm list --su prod", "az vm create -n x --s Standard_B1s"):
            with self.subTest(command=command):
                self.assertEqual(set(targets(command)), {(UNKNOWN, None)})

    def test_a_variable_anywhere_in_the_partition_is_unknown(self):
        for command in ('aws lambda create-function --function-name f --role "arn:aws-${P}" --runtime python3.12',
                        'aws lambda create-function --function-name f --role "arn:a${P}" --runtime python3.12',
                        'aws lambda create-function --function-name f --role "arn:aws-`echo cn`:iam::1:role/x"'):
            with self.subTest(command=command):
                self.assertEqual(targets(command), [(UNKNOWN, None)])

    def test_gsutil_long_options_between_the_short_ones(self):
        for command in ("gsutil mb --retention 1d -p acme-other-1 gs://b", "gsutil mb --pap enforced -p acme-other-1 gs://b",
                        "gsutil mb --autoclass -p acme-other-1 gs://b", "gsutil mb --retention=1d -l us -p acme-other-1 gs://b",
                        "gsutil --trace-token t -u acme-other-1 ls gs://b", "gsutil -o Credentials:x=y -u acme-other-1 ls gs://b"):
            with self.subTest(command=command):
                self.assertEqual(targets(command), [(ACCOUNT, "gcp:acme-other-1")])
        self.assertEqual(targets("gsutil -m rsync -u -r src gs://bucket"), [])

    def test_decoded_resource_ids_windows_names_env_pairs_and_runner_options(self):
        self.assertEqual(targets('az rest --uri "https://management.azure.com/subscriptions%%2F%s/x"' % GUID), [(ACCOUNT, "azure:" + GUID)])
        self.assertEqual(targets("aws.exe sts assume-role --role-arn arn:aws:iam::999988887777:role/x"), [(ACCOUNT, "aws:999988887777")])
        self.assertEqual(targets("env 'A-B=x/y' aws sts assume-role --role-arn arn:aws:iam::999988887777:role/x"),
                         [(ACCOUNT, "aws:999988887777")])
        self.assertIn((UNKNOWN, None), targets("uv run --a 1 --b 2 --c 3 --d 4 aws s3 ls"))
        self.assertEqual(targets("uv run --no-build-isolation-package x aws sts assume-role --role-arn arn:aws:iam::999988887777:role/x"),
                         [(ACCOUNT, "aws:999988887777")])

    # Third review of PR #135 (26c23c0).

    def test_a_dollar_after_a_word_ending_in_arn_is_not_an_arn(self):
        for command, want in (
                ('aws sns publish --topic-arn arn:aws:sns:us-east-1:111122223333:alerts --message "WARN: disk full on $HOST"',
                 [(ACCOUNT, "aws:111122223333")]),
                ("aws sns publish --topic-arn arn:aws:sns:us-east-1:111122223333:alerts --message 'Warn: cost is $5'",
                 [(ACCOUNT, "aws:111122223333")]),
                ("aws ssm send-command --document-name AWS-RunShellScript --parameters 'commands=[\"echo learn: $PATH\"]'", []),
                ('aws ec2 create-tags --resources i-1 --tags Key=Note,Value="barn: $X"', []),
                ('sam deploy --parameter-overrides Msg="warn: $X"', []), ('cdk deploy -c note="Learn: $X"', []),
                ('aws iam get-role --role-name "arn:aws-us-gov-${X}:iam::1:role/x"', [(UNKNOWN, None)]),
                ('aws iam get-role --role-name "arn:${P}:iam::1:role/x"', [(UNKNOWN, None)])):
            with self.subTest(command=command):
                self.assertEqual(targets(command), want)

    # Fourth review of PR #135 (9c2f010).

    def test_short_aws_abbreviations_with_a_file_or_json_value(self):
        for command in ("aws inspector2 enable --a file://ids.json", "aws inspector2 enable --ac fileb://ids.bin",
                        "aws quicksight list-users --aw file://acct.txt --namespace default",
                        "aws lambda add-permission --function-name f --sou '{\"a\":1}' --action x"):
            with self.subTest(command=command):
                self.assertEqual(targets(command), [(UNKNOWN, None)])
        self.assertEqual(targets("aws inspector2 enable --a '[\"999988887777\"]' --resource-types EC2"),
                         [(ACCOUNT, "aws:999988887777"), (UNKNOWN, None)])
        self.assertEqual(targets("aws inspector2 enable --a 999988887777 111122223333 --resource-types EC2"),
                         [(ACCOUNT, "aws:999988887777"), (ACCOUNT, "aws:111122223333")])
        # Only the first value is read as a possible account: --ac here is --acl, and the rest are positional.
        for command in ("aws s3 cp --ac private x s3://b/$KEY", "aws s3 cp --ac private x s3://b/999988887777x",
                        "aws codebuild create-project --source '{\"type\":\"S3\"}' --name x",
                        "aws codebuild create-project --source $SRC --name x"):
            with self.subTest(command=command):
                self.assertEqual(targets(command), [])

    def test_every_gsutil_project_option_is_read(self):
        # getopt keeps the last of several, and -u and a subcommand's -p each name a project.
        both = [(ACCOUNT, "gcp:good-project"), (ACCOUNT, "gcp:bad-project")]
        self.assertEqual(targets("gsutil -u bad-project -- ls gs://b"), [(ACCOUNT, "gcp:bad-project")])
        for command in ("gsutil -u good-project mb -p bad-project gs://b", "gsutil -u good-project ls -p bad-project",
                        "gsutil -u good-project -u bad-project ls gs://b", "gsutil mb -p good-project -p bad-project gs://b",
                        "gsutil -mu good-project -u bad-project ls"):
            with self.subTest(command=command):
                self.assertEqual(targets(command), both)

    def test_windows_cmd_names(self):
        for command, name in (("az.cmd account set --subscription %s" % GUID, "azure:" + GUID),
                              ("gcloud.cmd config set project acme-other-1", "gcp:acme-other-1"),
                              ("bq.cmd --project_id acme-other-1 ls", "gcp:acme-other-1"),
                              ("gsutil.cmd -u acme-other-1 ls", "gcp:acme-other-1")):
            with self.subTest(command=command):
                self.assertEqual(targets(command), [(ACCOUNT, name)])

    def test_coverage_is_an_exact_match(self):
        cases = [
            ("aws:123456789012", Target(ACCOUNT, "aws:123456789012"), True),
            ("aws:123456789012", Target(ACCOUNT, "aws:123456789013"), False),
            ("gcp:acme-prod-1", Target(ACCOUNT, "gcp:acme-prod-1"), True),
            ("gcp:acme-prod", Target(ACCOUNT, "gcp:acme-prod-1"), False),
            ("azure:" + GUID, Target(ACCOUNT, "azure:" + GUID), True),
            ("AZURE:" + GUID.upper(), Target(ACCOUNT, "azure:" + GUID), True),
            ("aws:123456789012", Target(ACCOUNT, "gcp:123456789012"), False),
            ("aws:123456789012", Target(UNKNOWN), False),
        ]
        for value, target, want in cases:
            with self.subTest(value=value, target=target):
                self.assertIs(account_covered(value, target), want)


def policy(values=("aws:111122223333", "gcp:acme-prod-1", "azure:" + GUID), mode="block", use_instead=None, extra=(), expires="2099-01-01"):
    rule = {"id": "cloud-accounts", "kind": "cloud_account", "mode": mode, "values": list(values)}
    if use_instead:
        rule["use_instead_text"] = use_instead
    return pol.parse(json.dumps({
        "format": "catpilot-company-policy", "format_version": 1, "source_sha256": "c" * 64, "expires_on": expires,
        "rules": [rule, *extra],
    }).encode())


def bash(command, permission_mode="default"):
    return {"session_id": "s1", "tool_name": "Bash", "tool_input": {"command": command}, "cwd": "/tmp", "permission_mode": permission_mode}


class FinalReviewCloudTests(unittest.TestCase):
    """The final review of #135: abbreviated aws options."""

    def test_short_options(self):
        cases = {
            # acm-pca's --source is --source-account: a 12-digit value is an account.
            "aws acm-pca create-permission --certificate-authority-arn arn:aws:acm-pca:us-east-1:111122223333:certificate-authority/x "
            "--principal acm.amazonaws.com --actions IssueCertificate --source 444455556666": ["aws:111122223333", "aws:444455556666"],
            # A variable after an account list is unknown; a timestamp inside a word is no account.
            "aws inspector2 enable --a 111122223333 $OTHER --resource-types EC2": ["aws:111122223333", None],
            "aws sts assume-role --role-arn arn:aws:iam::111122223333:role/r --role-session-name s --sou deploy-202611181200": ["aws:111122223333"],
            "aws kms create-alias --a alias/app-202611181200 --target-key-id k": [],
            "aws s3 cp --ac private x s3://b/$KEY": [],
            # JSON with leading space, as awscli strips it.
            "aws inspector2 enable --a ' [\"222233334444\"]' --resource-types EC2": ["aws:222233334444", None],
            "aws organizations describe-account --a 1234567890123": [],
        }
        for command, want in cases.items():
            with self.subTest(command=command):
                self.assertEqual(sorted(name or "" for _, name in targets(command)), sorted(w or "" for w in want))


class HookDecisionTests(unittest.TestCase):
    def setUp(self):
        self.lines = []
        patcher = mock.patch.object(cr, "record_evidence", lambda event, hook_event=None, host=None, **f: self.lines.append((event, f)))
        patcher.start()
        self.addCleanup(patcher.stop)

    def effect(self, command, host="claude-code", ask=False, permission_mode="default", **kw):
        result = cr.decide(bash(command, permission_mode), host, policy(**kw), ask_enabled=ask)
        return result.get("hookSpecificOutput", {}).get("permissionDecision", "none")

    def test_an_unlisted_account_fires_and_a_listed_one_does_not(self):
        self.assertEqual(self.effect("aws sts assume-role --role-arn arn:aws:iam::999988887777:role/x --role-session-name s"), "deny")
        self.assertEqual(self.effect("gcloud config set project personal-proj-1"), "deny")
        self.assertEqual(self.effect("az account set -s 'Pay-As-You-Go'"), "deny")  # a name: unknown, nothing covers it
        self.assertEqual(self.effect("gcloud run deploy --project $PROJECT"), "deny")
        self.assertEqual(self.effect("aws sts assume-role --role-arn arn:aws:iam::111122223333:role/x --role-session-name s"), "none")
        self.assertEqual(self.effect("gcloud config set project acme-prod-1"), "none")
        self.assertEqual(self.effect("az account set -s %s" % GUID.upper()), "none")
        self.assertEqual(self.effect("aws --profile personal s3 ls && gcloud run deploy && az group list"), "none")
        self.assertEqual([e for e, _ in self.lines], ["deny"] * 4)

    def test_every_account_must_be_covered(self):
        self.assertEqual(self.effect("gcloud config set project acme-prod-1 && gcloud run deploy --project other-proj-1"), "deny")

    def test_review_findings_fire(self):
        # Review of PR #135: each of these named an account the rule does not list and decided nothing.
        for command in ('aws iam attach-role-policy --role-name r --policy-arn "arn:aws:iam::$(cat other):policy/x"',
                        'aws iam attach-role-policy --role-name r --policy-arn "arn:${PARTITION}:iam::111122223333:policy/x"',
                        "aws organizations describe-account --account-i 999988887777", "az vm list --subs " + GUID.replace("a", "b"),
                        "uv run aws sts assume-role --role-arn arn:aws:iam::999988887777:role/x --role-session-name s",
                        "gsutil mb -p other-proj-1 gs://b", "echo x | xargs gcloud run deploy --project"):
            with self.subTest(command=command):
                self.assertEqual(self.effect(command), "deny")
        self.assertEqual(self.effect("uv run aws sts assume-role --role-arn arn:aws:iam::111122223333:role/x"), "none")

    def test_modes_hosts_and_expiry(self):
        command = "gcloud config set project personal-proj-1"
        self.assertEqual(self.effect(command, mode="monitor"), "none")
        self.assertEqual([(e, f["rule_id"], f["mode"]) for e, f in self.lines], [("would_deny", "cloud-accounts", "monitor")])
        self.assertEqual(self.effect(command, mode="ask"), "deny")
        self.assertEqual(self.effect(command, mode="ask", ask=True), "ask")
        self.assertEqual(self.effect(command, mode="ask", ask=True, host="codex"), "deny")
        self.assertEqual(self.effect(command, mode="ask", ask=True, permission_mode="auto"), "deny")
        self.lines.clear()
        self.assertEqual(self.effect(command, expires="2020-01-01"), "none")
        self.assertEqual([(e, f["mode"]) for e, f in self.lines], [("would_deny", "monitor")])

    def test_the_reason_and_evidence_name_the_rule_never_the_account(self):
        command = ("aws sts assume-role --role-arn arn:aws:iam::%s:role/x --role-session-name s && gcloud config set project %s "
                   "&& az account set -s %s" % (MARKER_AWS, MARKER_GCP, MARKER_AZURE))
        result = cr.decide(bash(command), "claude-code",
                           policy(values=("aws:" + MARKER_AWS[::-1], "gcp:%s-2" % MARKER_GCP, "azure:" + MARKER_AZURE[::-1]),
                                  use_instead="The approved cloud subscription managed by IT"))
        reason = result["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("Catpilot company rule `cloud-accounts`: not an approved cloud account.", reason)
        self.assertIn("Use instead: The approved cloud subscription managed by IT.", reason)
        for text in (MARKER_AWS, MARKER_AWS[::-1], MARKER_GCP, MARKER_AZURE, MARKER_AZURE[::-1], "assume-role", "gcloud", "az "):
            self.assertNotIn(text, reason)
        self.assertEqual(self.lines, [("deny", {"tool": "Bash", "rule_id": "cloud-accounts", "mode": "block", "policy_sha256": "c" * 64})])

    def test_registry_and_account_rules_together(self):
        registries = {"id": "package-registries", "kind": "package_registry", "mode": "monitor", "values": ["npm.example.org"]}
        result = cr.decide(bash("npm publish --registry https://registry.npmjs.org && gcloud config set project personal-proj-1"),
                           "claude-code", policy(mode="ask", extra=(registries,)), ask_enabled=True)
        self.assertEqual(result["hookSpecificOutput"]["permissionDecision"], "ask")
        reason = result["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("`cloud-accounts`", reason)
        self.assertNotIn("package-registries", reason)  # monitor: logged, not part of the decision
        self.assertEqual(sorted((e, f["rule_id"]) for e, f in self.lines), [("ask", "cloud-accounts"), ("would_deny", "package-registries")])


class HookProcessTests(unittest.TestCase):
    """The shim as the host runs it, with a cloud_account policy: the decision, and an evidence log without the account."""

    def test_denies_and_logs_content_free(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "policy"
            directory.mkdir()
            os.chmod(directory, 0o755)
            path = directory / "company-policy.json"
            path.write_text(json.dumps({"format": "catpilot-company-policy", "format_version": 1, "source_sha256": "d" * 64,
                                        "expires_on": "2099-01-01", "rules": [
                                            {"id": "cloud-accounts", "kind": "cloud_account", "mode": "ask",
                                             "values": ["gcp:%s-2" % MARKER_GCP, "aws:" + MARKER_AWS[::-1]]}]}), encoding="utf-8")
            os.chmod(path, 0o644)
            log = Path(tmp) / "evidence.jsonl"
            env = {k: v for k, v in os.environ.items() if not k.startswith("CATPILOT_EVIDENCE")}
            env["CATPILOT_EVIDENCE_LOG"] = str(log)
            command = "aws organizations describe-account --account-id %s" % MARKER_AWS
            proc = subprocess.run([sys.executable, str(HOOK), "--policy", str(path)], input=json.dumps(bash(command)),
                                  capture_output=True, text=True, env=env, timeout=30)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            output = json.loads(proc.stdout)["hookSpecificOutput"]
            self.assertEqual(output["permissionDecision"], "deny")  # ask without --ask acts as block
            self.assertIn("nobody can be asked here", output["permissionDecisionReason"])
            (line,) = [json.loads(x) for x in log.read_text(encoding="utf-8").splitlines()]
            self.assertEqual((line["event"], line["rule_id"], line["mode"]), ("deny", "cloud-accounts", "ask"))
            everything = log.read_text(encoding="utf-8") + proc.stdout + proc.stderr
            for text in (MARKER_AWS, MARKER_AWS[::-1], MARKER_GCP):
                self.assertNotIn(text, everything)


class VerifyProbeTests(unittest.TestCase):
    """verify.sh's stdlib copy of the coverage, and its probes, agree with the hook (deploy/org/session_start_files.py)."""

    def setUp(self):
        spec = importlib.util.spec_from_file_location("session_start_files_for_accounts", ROOT / "deploy" / "org" / "session_start_files.py")
        self.helper = importlib.util.module_from_spec(spec)
        previous = sys.dont_write_bytecode
        sys.dont_write_bytecode = True
        try:
            spec.loader.exec_module(self.helper)
        finally:
            sys.dont_write_bytecode = previous

    def test_the_copy_of_the_coverage_agrees(self):
        values = ("aws:000000000000", "AWS:000000000000", "aws:111122223333", "gcp:catpilot-verify-probe", "gcp:catpilot-verify",
                  "azure:00000000-0000-0000-0000-00000000c0de", "azure:00000000-0000-0000-0000-00000000C0DE")
        for value in values:
            for _, name in self.helper.CLOUD_PROBES:
                with self.subTest(value=value, name=name):
                    self.assertEqual(self.helper.account_covered(value, name), account_covered(value, Target(ACCOUNT, name)))

    def test_the_hook_reads_each_probe_as_the_helper_expects(self):
        for command, name in self.helper.CLOUD_PROBES:
            with self.subTest(command=command):
                self.assertEqual(targets(command), [(ACCOUNT, name)])

    def test_the_probe_falls_outside_the_first_rule(self):
        def probe(rules, expires="2099-01-01"):
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "policy.json"
                path.write_text(json.dumps({"expires_on": expires, "rules": rules}), encoding="utf-8")
                return self.helper.first_cloud_probe(path)

        rule = lambda rule_id, mode, values: {"id": rule_id, "kind": "cloud_account", "mode": mode, "values": values}  # noqa: E731
        found = probe([rule("cloud-accounts", "ask", ["aws:111122223333"])])
        self.assertEqual((found[0], found[1], found[3], found[4]), ("cloud-accounts", "ask", False, ["ask"]))
        self.assertIn("000000000000", found[2])
        found = probe([rule("a", "block", ["aws:000000000000"]), rule("b", "monitor", ["gcp:catpilot-verify-probe"])])
        self.assertIn("gcloud config set project", found[2])
        self.assertEqual(found[4], ["block"])  # b covers this probe
        self.assertIsNone(probe([{"id": "d", "kind": "deploy_host", "mode": "block", "values": ["apps.example.org"]}]))
        for command, _ in self.helper.CLOUD_PROBES:  # the hook, not only the helper, reads it as outside the rule
            with mock.patch.object(cr, "record_evidence", lambda *a, **k: None):
                self.assertEqual(cr.decide(bash(command), "claude-code", policy())["hookSpecificOutput"]["permissionDecision"], "deny")


class CompoundCommandCloudTests(unittest.TestCase):
    """#137's compound-command and comment forms reach the cloud-account reader through split_command."""

    def test_accounts_inside_compound_commands_and_after_comment_forms(self):
        cases = {
            "{ aws s3 ls --profile x --account-id 999999999999; }": "aws:999999999999",
            "if true; then aws organizations describe-account --account-id 999999999999; fi": "aws:999999999999",
            "until false; do aws sts assume-role --role-arn arn:aws:iam::999988887777:role/x --role-session-name s; done":
                "aws:999988887777",
            "for p in a; do gcloud run deploy svc --project other-proj-1; done": "gcp:other-proj-1",
            "while true; do gcloud config set project personal-proj-1; break; done": "gcp:personal-proj-1",
            "f() { gcloud config set project personal-proj-1; }; f": "gcp:personal-proj-1",
            "case a in a) gcloud run deploy svc --project other-proj-1;; esac": "gcp:other-proj-1",
            "! gcloud run deploy svc --project other-proj-1": "gcp:other-proj-1",
            "if true; then AWS_ROLE_ARN=arn:aws:iam::999988887777:role/ci aws s3 ls; fi": "aws:999988887777",
            "echo a\\ #; gcloud config set project personal-proj-1": "gcp:personal-proj-1",
            "ls # note \\\ngcloud config set project personal-proj-1": "gcp:personal-proj-1",
            "echo $'\\'' ; gcloud config set project personal-proj-1 ; echo \\'": "gcp:personal-proj-1",
        }
        for command, want in cases.items():
            with self.subTest(command=command):
                self.assertIn((ACCOUNT, want), targets(command))

    def test_the_hook_decides_on_them(self):
        def effect(command):
            result = cr.decide(bash(command), "claude-code", policy())
            return result.get("hookSpecificOutput", {}).get("permissionDecision", "none")

        with mock.patch.object(cr, "record_evidence", lambda *a, **k: None):
            self.assertEqual(effect("{ aws s3 ls --profile x --account-id 999999999999; }"), "deny")
            self.assertEqual(effect("if true; then gcloud config set project personal-proj-1; fi"), "deny")
            self.assertEqual(effect("if true; then gcloud config set project acme-prod-1; fi"), "none")
            self.assertEqual(effect("gcloud config set project acme-prod-1\r\n"), "none")


if __name__ == "__main__":
    unittest.main()
