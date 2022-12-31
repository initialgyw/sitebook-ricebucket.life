#!/usr/bin/env bash

<<COMMENT
Creates the following:
- service account for Terraform
- group to add the service account to
- compartment to store Terraform resources
- policies for terraform group to manage terraform compartment
- vault to store secrets
- bucket to store Terraform state file
COMMENT

set -o errexit    # exit if command fails
set -o nounset    # exit if variables are unset
set -o pipefail   # exit if pipe commands fail

# source common functions
SCRIPTPATH=$(cd -- $(dirname $0) > /dev/null 2>&1; pwd -P)
source ${SCRIPTPATH}/common.sh

function usage() {
    echo "Usage: $(basename $0)"
    echo '  -h | --help              Show this menu'
    echo '  -r | --region            REQUIRED[str]: Primary region for the OCI account'
    echo '  -t | --tenancy           REQUIRED[str]: Tenancy name for the OCI account'
    echo '  -u | --tf-user           OPTIONAL[str]: Name of the service account to use for tf. Default = sa-tf'
    echo '  -c | --config-file       OPTIONAL[str]: Provide the location of the configuration file. Defaults = ~/.oci/config'
    echo '  -p | --profile           OPTIONAL[str]: Profile name for the configuration. If not provided, it will be set to Tenancy name'
    echo '  --configure-tf-backend   OPTIONAL[bool]: Ensure Vault and TF storage resources are created. Default = False'
    echo '  --automation-compartment OPTIONAL[str]: Compartment name to store Vault and tf backend. Will create if --configure-tf-backend is set. Default = cpm-automation'
    echo '  --api-key                OPTIONAL[str]: Location of the API key to use for tf-user. Default = sa-terrafrom'
    echo '  --tf-group               OPTIONAL[str]: Group to add tf user into. Default = group-tf'
    echo '  --tf-compartment         OPTIONAL[str]: Compartment name to store all tf created resources. Default = cpm-tf'
    echo '  -v | --verbose           OPTIONAL[bool]: Set logging to DEBUG. Default = INFO'
}

# setting initial variables
profile=
region=
tenancy=
private_rsa_key_path=''
sa_tf='sa-terraform'
group_tf='group-terraform'
compartment_tf='cpm-terraform'
compartment_automation='cpm-automation'
configure_tf_backend=0
script_log_level='INFO'
config_file="${HOME}/.oci/config"
tmp_file="/tmp/$(basename $0 | sed 's/$/.tmp/g')"

# Disable warning permissions for config file
export OCI_CLI_SUPPRESS_FILE_PERMISSIONS_WARNING=True

# getting user input
LONG_OPTIONS='help,verbose,configure-tf-backend,tenancy:,region:,profile:,config-file:,tf-user:,api-key:,tf-group:,automation-compartment:'
SHORT_OPTIONS='hvt:r:p:c:u'
OPTIONS=$(getopt -o ${SHORT_OPTIONS} --long ${LONG_OPTIONS} -- "$@")
[ $? != 0 ] && usage >&2 && exit 1
eval set -- "$OPTIONS"

[ $# -le 1 ] && __log 'ERROR' 'No options provided' && usage && exit 1
while true; do
    case "$1" in
        -h | --help) usage && exit 0 ;;
        -v | --verbose) script_log_level='DEBUG'; shift ;;
        -r | --region) region="$2"; shift 2 ;;
        -u | --sa-tf-name) sa_tf="$2"; shift 2 ;;
        -t | --tenancy) tenancy="$2"; shift 2 ;;
        -p | --profile) profile="$2"; shift 2 ;;
        -c | --config-file) config_file="$2"; shift 2 ;;
        --api-key) private_rsa_key_path="$2"; shift 2 ;;
        --configure-tf-backend) configure_tf_backend=1; shift ;;
        --tf-group) group_tf="$2"; shift 2 ;;
        --tf-compartment) terrafrom_compartment="$2"; shift 2 ;;
        --automation-compartment) compartment_automation="$2"; shift 2 ;;
        --) shift; break ;;
        *) log 'ERROR' "Unknown option: ${1}" && usage && exit 1 ;;
  esac
done

# script requirements
required_apps=(oci)
for app in ${required_apps[@]}; do
    check_required_app "${app}" || (__log 'ERROR' "App not installed or in PATH: ${app}" && exit 1)
    __log 'DEBUG' "App detected in PATH: ${app}"
done

# variables validations
for var in tenancy region; do
    [ -z "${!var}" ] && __log 'ERROR' "${var} is required." && exit 1
    __log 'DEBUG' "VAR: $var = ${!var}"
done

if [ -z ${profile} ]; then
    profile="${tenancy}"
fi
__log 'DEBUG' "VAR: profile = ${profile}"

# variables based on input
OCI="oci --config-file ${config_file} --profile ${profile} --auth security_token"
[ -z $private_rsa_key_path ] && private_rsa_key_path="${HOME}/.oci/${tenancy}-${sa_tf}.key"
public_rsa_key_path=$(echo ${private_rsa_key_path} | sed 's/.key$//' | sed 's/$/.pub/g')
__log 'DEBUG' "VAR private_rsa_key_path = ${private_rsa_key_path}"
__log 'DEBUG' "VAR public_rsa_key_path = ${public_rsa_key_path}"
__log 'DEBUG' "VAR tmp_file = ${tmp_file}"

# ########################
# Script tasks starts here
# ########################

source ${SCRIPTPATH}/oci.sh || exit 1

# check for valid token
cmd_check_valid_session="oci session validate"
cmd_check_valid_session+=" --profile ${profile} --config-file ${config_file} --region ${region} --local"

cmd_session_authenticate="oci session authenticate"
cmd_session_authenticate+=" --config-location ${config_file} --profile-name ${profile} --region ${region} --tenancy-name ${tenancy}"

run_oci_command "${cmd_check_valid_session}" || (run_oci_command "${cmd_session_authenticate}" && run_oci_command "${cmd_check_valid_session}")
__log 'DEBUG' "Current session is valid."

# get all users in account
cmd_get_users="${OCI} iam user list"
run_oci_command "${cmd_get_users}" || (__log 'ERROR' 'Unable to get list of users. Do you have permission to view user list?' && exit 1)
users=$(cat $tmp_file)

# get root compartment OCID
ocid_cpm_root=$(echo "${users}" | jq -r '.data[0]."compartment-id"')

# tf SERVICE ACCOUNT

# check for tf service account
ocid_sa_tf=$(echo "$users" | jq -r --arg USER "$sa_tf" '.data[] | select(.name==$USER) | .id')

# create tf service account
sa_tf_capabilities=''
if [ -z "$ocid_sa_tf" ]; then
    __log 'INFO' "${sa_tf} service account does not exist. Will create."

    cmd_create_sa_tf="${OCI} iam user create --name ${sa_tf} --description service_account-tf"
    run_oci_command "${cmd_create_sa_tf}" || (__log 'CRITICAL' "Unable to create ${sa_tf} account" && exit 1)
    ocid_sa_tf=$(cat $tmp_file | jq -r '.data.id')
    sa_tf_capabilities=$(cat $tmp_file | jq -r '.data.capabilities')
    __log 'DEBUG' "VAR ocid_sa_tf = $ocid_sa_tf"

    declare -A sa_tf_capabilities_update=(
        [can-use-console-password]=false
        [can-use-api-keys]=false
        [can-use-auth-tokens]=false
        [can-use-customer-secret-keys]=false
        [can-use-db-credentials]=false
        [can-use-o-auth2-client-credentials]=false
        [can-use-smtp-credentials]=false)
    [ $configure_tf_backend -eq 1 ] && sa_tf_capabilities_update[can-use-customer-secret-keys]=true
    [ ! -z $private_rsa_key_path ] && sa_tf_capabilities_update[can-use-api-keys]=true
    update_user_capabilities $ocid_sa_tf "${sa_tf_capabilities}" sa_tf_capabilities_update || (__log 'ERROR' "Unable to update ${sa_tf} capabilities" && exit 1)
    sa_tf_capabilities=$(cat $tmp_file | jq -r '.data.capabilities')
else
    __log 'INFO' "${sa_tf} (${ocid_sa_tf}) service account already exists."
    sa_tf_capabilities=$(echo "$users" | jq -r --arg USER "$sa_tf" '.data[] | select(.name==$USER) | .capabilities')
fi

# ensure tf service account has can-use-api-keys capability
declare -A sa_tf_capabilities_update=([can-use-api-keys]=true)
update_user_capabilities $ocid_sa_tf "${sa_tf_capabilities}" sa_tf_capabilities_update || (__log 'ERROR' "Unable to update ${sa_tf} capabilities" && exit 1)

# get list of keys for sa-tf
gen_api_key=1
private_rsa_key_md5=
sa_tf_api_keys_total_num=

cmd_get_sa_tf_api_keys="${OCI} iam user api-key list --user-id ${ocid_sa_tf}"
run_oci_command "${cmd_get_sa_tf_api_keys}" || (__log 'ERROR' "Unable to get list of keys for ${sa_tf}" && exit 1)
sa_tf_api_keys=$(cat "$tmp_file")
if [ ! -s $tmp_file ]; then
    gen_api_key=1
else
    sa_tf_api_keys_total_num=$(echo "${sa_tf_api_keys}" | jq -r '.data | length')
fi

if [ ! -f $private_rsa_key_path ]; then
    gen_api_key=1
else
    if ! get_rsa_key_md5 $private_rsa_key_path; then
        __log 'WARNING' "Unable to get MD5 of ${private_rsa_key_path}. Recreating key."
        gen_api_key=1
    else
        private_rsa_key_md5=$(cat ${tmp_file} | awk -F\= '{ gsub(/ /,""); print $2}')
        __log 'DEBUG' "VAR private_rsa_key_md5 = ${private_rsa_key_md5}"
    fi
fi

# compare local key with all the keys on sa-tf
if [ ! -z "${private_rsa_key_md5}" ]; then
    for fingerprint in $(echo "${sa_tf_api_keys}" | jq -r '.data[].fingerprint'); do
        if [[ "${fingerprint}" == "${private_rsa_key_md5}" ]]; then
            __log 'DEBUG' "${private_rsa_key_path} (${fingerprint}) RSA key detected in ${sa_tf} API key list"
            gen_api_key=0
        fi
    done
    [ $gen_api_key -eq 1 ] && __log 'WARN' "${private_rsa_key_path} was not uploaded to ${sa_tf}."
fi

# generate RSA key for sa-tf
if [ $gen_api_key -eq 1 ]; then
    [[ $sa_tf_api_keys_total_num -ge 3 ]] && __log 'ERROR' "More than 3 API keys already exists for ${sa_tf}. Delete one." && exit 1

    if [ ! -f $private_rsa_key_path ]; then
        generate_private_rsa_api_key $private_rsa_key_path || exit 1
        generate_public_rsa_api_key $private_rsa_key_path $public_rsa_key_path || exit 1
    else
        if ! generate_public_rsa_api_key $private_rsa_key_path $public_rsa_key_path; then
            __log 'ERROR' "Unable to generate ${public_rsa_key_path} from ${private_rsa_key_path}. Regenerating a new key."
            generate_private_rsa_api_key $private_rsa_key_path || exit 1
            generate_public_rsa_api_key $private_rsa_key_path $public_rsa_key_path || exit 1
        fi
    fi

    cmd_sa_tf_upload_key="${OCI} iam user api-key upload --user-id ${ocid_sa_tf} --key-file ${public_rsa_key_path}"
    run_oci_command "${cmd_sa_tf_upload_key}" || (__log 'ERROR' "Unable to upload ${public_rsa_key_path} to ${sa_tf}" && exit 1)
    __log 'SUCCESS' "Successfully uploaded ${public_rsa_key_path} to ${sa_tf}."
    private_rsa_key_md5=$(cat $tmp_file | jq -r '.data.fingerprint')
fi
update_file_permission $private_rsa_key_path || exit 1

# update config to include sa-tf
declare -A sa_tf_profile_config=(
    [name]="[${sa_tf}]"
    [user]="${ocid_sa_tf}"
    [fingerprint]="${private_rsa_key_md5}"
    [tenancy]="${ocid_cpm_root}"
    [region]="${region}"
    [key_file]="${private_rsa_key_path}"
)
update_ini_file sa_tf_profile_config $config_file $tmp_file || (__log 'ERROR' "Unable to update ${config_file} with ${sa_tf} profile settings" && exit 1)
update_file_permission $config_file

# TERRAFORM GROUP

# create tf group
cmd_get_groups="${OCI} iam group list"
run_oci_command "${cmd_get_groups}" || (__log 'ERROR' "Unable to get group list" && exit 1)
ocid_group_tf=$(cat $tmp_file | jq -r --arg GROUP "${group_tf}" '.data[] | select(.name==$GROUP) | .id')
__log 'DEBUG' "VAR group_tf = ${group_tf}"

if [ -z "${ocid_group_tf}" ]; then
    __log 'WARN' "group-tf does not exist. Will create."
    cmd_create_group_tf="${OCI} iam group create --name ${group_tf} --description group_tf"
    run_oci_command "${cmd_create_group_tf}" || (__log 'CRITICAL' "Unable to create tf group" && exit 1)
    ocid_group_tf=$(cat $tmp_file | jq -r '.data.id')
    __log 'SUCCESS' "Created ${group_tf}: ${ocid_group_tf}"
else
    __log 'INFO' "${group_tf} already exists."
fi

# check to see if sa_tf is in tf group
cmd_get_group_tf_users="${OCI} iam group list-users --group-id ${ocid_group_tf}"
run_oci_command "${cmd_get_group_tf_users}" || (__log 'CRITICAL' "Unable to get ${group_tf} member list" && exit 1)
group_tf_users=$(cat $tmp_file | jq -r '.data[].name')

add_sa_tf_to_group=1
for user in ${group_tf_users[@]}; do
    if [[ "${user}" == "${sa_tf}" ]]; then 
        __log 'DEBUG' "${sa_tf} user detected in ${group_tf}"
        add_sa_tf_to_group=0
        break
    fi
done

if [ $add_sa_tf_to_group -eq 1 ]; then
    __log 'INFO' "Adding ${sa_tf} to ${group_tf}"
    cmd_add_sa_tf_to_group_tf="${OCI} iam group add-user --user-id ${ocid_sa_tf} --group-id ${ocid_group_tf}"
    run_oci_command "${cmd_add_sa_tf_to_group_tf}" || (__log 'CRITICAL' "Unable to add ${sa_tf} to ${group_tf}" && exit)
    __log 'SUCCESS' "Successfully added ${sa_tf} to ${group_tf}"
fi

# TERRAFORM COMPARTMENT

# create compartment to hold resources created by tf
cmd_get_compartments="${OCI} iam compartment list"
run_oci_command "${cmd_get_compartments}" || (__log 'ERROR' 'Unable to get list of compartments' && exit 1)
compartments=$(cat $tmp_file)
ocid_compartment_tf=$(echo "${compartments}" | jq -r --arg CPM "$compartment_tf" '.data[] | select(.name==$CPM and ."lifecycle-state"=="ACTIVE") | .id')

if [ -z $ocid_compartment_tf ]; then
    __log 'INFO' "${compartment_tf} does not exist. Will create."

    cmd_create_compartment="${OCI} iam compartment create"
    cmd_create_compartment+=" --name ${compartment_tf} --compartment-id ${ocid_cpm_root} --description stores_terraform_created_resources"

    run_oci_command "${cmd_create_compartment}" || (__log 'ERROR' "Unable to create ${compartment_tf}" && exit 1)
    __log 'SUCCESS' "Successfully created ${compartment_tf}: $(cat $tmp_file | jq -r '.data.id')"
    ocid_compartment_tf=$(cat $tmp_file | jq -r '.data.id')
else
    __log 'INFO' "${compartment_tf} already created"
fi
__log 'DEBUG' "VAR ocid_compartment_tf = ${ocid_compartment_tf}"

# configure policy to allow group-tf to administrate cpm-tf
policy_name="policy-${group_tf}"
cmd_get_root_policies="${OCI} iam policy list --compartment-id ${ocid_cpm_root}"
run_oci_command "${cmd_get_root_policies}" || (__log 'ERROR' "Unable to get root policies." && exit 1)
policy_group_tf=$(cat $tmp_file | jq -r --arg POLICYNAME "${policy_name}" '.data[] | select(.name==$POLICYNAME and ."lifecycle-state"=="ACTIVE")')
policy_group_tf_statements=$(echo "${policy_group_tf}" | jq -r '.statements')
ocid_policy_group_tf=$(echo "${policy_group_tf}" | jq -r '.id')

declare -a required_policy_group_tf_statements=(
    "Allow group ${group_tf} to manage all-resources in compartment ${compartment_tf}"
)

if [ -z "${policy_group_tf_statements}" ]; then
    policy_statements=$(printf '%s\n' "${required_policy_group_tf_statements[@]}" | jq -R . | jq -s .)
else
    required_statements=$(printf '%s\n' "${required_policy_group_tf_statements[@]}" | jq -R . | jq -s .)
    policy_statements=$(jq '[.[0][], .[1][]] | unique' <<< "[$required_statements, $policy_group_tf_statements]")
fi

if ! diff <(echo "${policy_statements}" | jq . -S) <(echo "${policy_group_tf_statements}" | jq . -S) > /dev/null; then
    echo "${policy_statements}" > ${tmp_file}.json

    if [ ! -z "${policy_group_tf_statements}" ]; then
        cmd_set_policy="${OCI} iam policy update"
        cmd_set_policy+=" --policy-id ${ocid_policy_group_tf} --statements file://${tmp_file}.json --version-date $(date +%Y-%m-%d) --force"
    else
        cmd_set_policy="${OCI} iam policy create --compartment-id ${ocid_cpm_root}"
        cmd_set_policy+=" --name ${policy_name} --description policy_for_${group_tf} --statements file://${tmp_file}.json"
    fi

    run_oci_command "${cmd_set_policy}" || (__log 'ERROR' "Unable to create policy ${policy_group_tf}" && exit 1)
    __log 'SUCCESS' "Successfully set policies ${policy_group_tf}"
    policy_group_tf_statements="${policy_statements}"
else
    __log 'INFO' "${policy_name} already allows ${group_tf} to manage ${compartment_tf}"
fi

[ $configure_tf_backend -eq 0 ] && __log 'SUCCESS' 'Done!' && exit 0

# CONFIGURE TF BACKEND

# create compartment to store Vault and TF storage
ocid_compartment_automation=$(echo "${compartments}" | jq -r --arg CPM "$compartment_automation" '.data[] | select(.name==$CPM and ."lifecycle-state"=="ACTIVE") | .id')
if [ -z $ocid_compartment_automation ]; then
    __log 'INFO' "${compartment_automation} does not exist. Will create."

    cmd_create_compartment="${OCI} iam compartment create"
    cmd_create_compartment+=" --name ${compartment_automation} --compartment-id ${ocid_cpm_root} --description stores_tf_created_resources"

    run_oci_command "${cmd_create_compartment}" || (__log 'ERROR' "Unable to create ${compartment_automation}" && exit 1)
    __log 'SUCCESS' "Successfully created ${compartment_automation}: $(cat $tmp_file | jq -r '.data.id')"
    ocid_compartment_automation=$(cat $tmp_file | jq '.data.id')
else
    __log 'INFO' "${compartment_automation} already created."
fi
__log 'DEBUG' "VAR ocid_compartment_tf = ${ocid_compartment_automation}"

# create os bucket to store tf state files
cmd_get_storage_in_cpm_automation="${OCI} os bucket list --compartment-id ${ocid_compartment_automation}"
run_oci_command "${cmd_get_storage_in_cpm_automation}" || (__log 'ERROR' "Unable to get list of buckets in ${compartment_automation}" && exit 1)
tf_storage=$(cat $tmp_file | jq -r '.data[] | select(.name == "bucket-terraform") | .id')

if [ -z "${tf_storage}" ]; then
    # get os namespace
    cmd_get_os_namespace="${OCI} os ns get"
    run_oci_command "${cmd_get_os_namespace}" || (__log 'CRITICAL' "Unable to get os namespace" && exit 1)
    os_namespace=$(cat $tmp_file | jq -r '.data')
    __log 'DEBUG' "VAR os_namespace = ${os_namespace}"

    # create bucket
    cmd_create_tf_bucket="${OCI} os bucket create --name bucket-terraform"
    cmd_create_tf_bucket+=" --namespace ${os_namespace}  --compartment-id ${ocid_compartment_automation} --versioning Enabled"
    run_oci_command "${cmd_create_tf_bucket}" || (__log 'CRITICAL' "Unable to create bucket-terraform" && exit 1)
    __log 'SUCCESS' "bucket-terraform created."
else
    __log 'DEBUG' 'bucket-terraform already exists.'
fi

# create Vault to store secrets
vault_name="vault-automation"
cmd_get_vault_list_in_cpm_automation="${OCI} kms management vault list --compartment-id ${ocid_compartment_automation}"
run_oci_command "${cmd_get_vault_list_in_cpm_automation}" || (__log 'CRITICAL' "Unable to get list of vault in cpm-automation" && exit 1)
tf_vault_management_endpoint=$(cat $tmp_file | jq -r --arg NAME "${vault_name}" '.data[] | select(."display-name"==$NAME and (."lifecycle-state"=="ACTIVE" or ."lifecycle-state"=="CREATING")) | ."management-endpoint"')

if [ -z "${tf_vault_management_endpoint}" ]; then
    cmd_create_terraform_vault="${OCI} kms management vault create --compartment-id ${ocid_compartment_automation} --display-name ${vault_name} --vault-type DEFAULT"
    run_oci_command "${cmd_create_terraform_vault}" || (__log 'ERROR' "Unable to create ${vault_name} in ${compartment_automation}" && exit 1)
    ocid_vault=$(cat $tmp_file | jq -r '.data.id')

    cmd_get_vault="${OCI} kms management vault get --vault-id ${ocid_vault}"
    while true; do
        run_oci_command "${cmd_get_vault}" || (__log 'CRITICAL' "Unable to get state of newly created vault." && exit 1)
        tf_vault_state=$(cat $tmp_file | jq -r '.data."lifecycle-state"')

        if [[ "${tf_vault_state}" == 'CREATING' ]]; then
            __log 'INFO' "vault-terraform is still in ${tf_vault_state} state. Sleeping for 5 seconds."
            sleep 5
            continue
        elif [[ "${tf_vault_state}" == 'ACTIVE' ]]; then
            tf_vault_management_endpoint=$(cat $tmp_file | jq -r '.data."management-endpoint"')
            break
        else
            __log 'ERROR' "vault-terraform is in ${tf_vault_state} state." && exit 1
        fi
    done
else
    __log 'INFO' "vault-terraform already exists."
fi
__log 'DEBUG' "VAR tf_vault_management_endpoint = ${tf_vault_management_endpoint}"

# create vault key
cmd_get_tf_vault_keys="${OCI} kms management key list --compartment-id ${ocid_compartment_automation} --endpoint ${tf_vault_management_endpoint} --all"
run_oci_command "${cmd_get_tf_vault_keys}" || (__log 'CRITICAL' "Unable to get keys for vault-terraform" && exit 1)
tf_vault_key=$(cat $tmp_file | jq -r '.data[] | select(."display-name" == "vault-key" and (."lifecycle-state"=="ENABLED" or ."lifecycle-state"=="CREATING")) | .id')

if [ -z "${tf_vault_key}" ]; then
    key_shape='{"algorithm":"AES","length":"32"}'
    cmd_create_tf_vault_key="${OCI} kms management key create --compartment-id ${ocid_compartment_automation}"
    cmd_create_tf_vault_key+=" --display-name vault-key --key-shape $(echo ${key_shape}) --endpoint ${tf_vault_management_endpoint}"
    run_oci_command "${cmd_create_tf_vault_key}" || (__log 'CRITICAL' "Unable to create key for vault-terraform" && exit 1)
else
    __log 'DEBUG' 'vault-terraform-key is active for vault-terraform'
fi

# update policy for group-terraform to access storage bucket and vault
declare -a required_policy_group_tf_statements=(
    "Allow group ${group_tf} to manage objects in compartment ${compartment_automation} where target.bucket.name='bucket-terraform'"
    "Allow group ${group_tf} to read secret-family in compartment ${compartment_automation}"
)

required_statements=$(printf '%s\n' "${required_policy_group_tf_statements[@]}" | jq -R . | jq -s .)
policy_statements=$(jq '[.[0][], .[1][]] | unique' <<< "[$required_statements, $policy_group_tf_statements]")

if ! diff <(echo "${policy_statements}" | jq . -S) <(echo "${policy_group_tf_statements}" | jq . -S) > /dev/null; then
    echo "${policy_statements}" > ${tmp_file}.json
    #echo "${policy_statements}" | jq .
    cmd_update_policy="${OCI} iam policy update"
    cmd_update_policy+=" --policy-id ${ocid_policy_group_tf} --statements file://${tmp_file}.json --version-date $(date +%Y-%m-%d) --force"

    run_oci_command "${cmd_update_policy}" || (__log 'ERROR' "Unable to create policy ${policy_group_tf}" && exit 1)
    __log 'SUCCESS' "Successfully updated ${policy_group_tf}"
else
    __log 'INFO' "${policy_name} already allows ${group_tf} to read Vault Secrets and update Terraform storage in ${compartment_tf}"
fi

# generate customer-secret-key for sa_tf to access buckets

# ensure sa_tf can create customer-secret-key
create_customer_secret=1
sa_tf_capabilities_update=()
sa_tf_capabilities_update[can-use-customer-secret-keys]=true
update_user_capabilities $ocid_sa_tf "${sa_tf_capabilities}" sa_tf_capabilities_update || (__log 'ERROR' "Unable to update ${sa_tf} capabilities" && exit 1)

# list customer secrets
cmd_get_customer_secret_keys="${OCI} iam customer-secret-key list --user-id ${ocid_sa_tf}"
run_oci_command "${cmd_get_customer_secret_keys}" || (__log 'ERROR' "Unable to get customer secret keys from ${sa_tf}" && exit 1)
sa_tf_secret_keys=$(cat $tmp_file | jq -r '.data[] | select(."display-name"=="access_tf_bucket" and ."lifecycle-state"=="ACTIVE")')

declare -A sa_tf_customer_secret_key=(
    [name]="[oci-${tenancy}-${sa_tf}]"
    [aws_access_key_id]=''
    [aws_secret_access_key]=''
)

[ -z "${sa_tf_secret_keys}" ] && __log 'INFO' "No customer key exists for ${sa_tf}. Will create."

storage_credentials_file="${HOME}/.aws/credentials"

if get_ini_section "[oci-${tenancy}-${sa_tf}]" "${storage_credentials_file}" "$tmp_file"; then
    aws_access_key_id=$(grep aws_access_key_id $tmp_file | cut -d= -f2 | xargs)
    __log 'DEBUG' "VAR aws_access_key_id = ${aws_access_key_id}"

    for key_id in $(echo "${sa_tf_secret_keys}" | jq -r '.id'); do
        if [[ "${aws_access_key_id}" == "${key_id}" ]]; then
            __log 'INFO' "Customer secret key is already set in ${storage_credentials_file}"
            create_customer_secret=0
            break
        fi
    done
    [ $create_customer_secret -eq 1 ] && __log 'DEBUG' "Customer secret key not saved to ${storage_credentials_file}"
fi

if [ $create_customer_secret -eq 1 ]; then
    if [ $(echo "${sa_tf_secret_keys}" | jq -r '.id' | wc -l) -ge 2 ]; then
        __log 'ERROR' "Unable to create new customer secret keys due to hitting 2 limit. Please delete one" && exit 1
    fi

    if [ ! -f "${storage_credentials_file}" ]; then
        if [ ! -d $(dirname "${storage_credentials_file}") ]; then
            mkdir -p "$(dirname ${storage_credentials_file})" || (__log 'ERROR' "Unable to create directory: $(dirname ${storage_credentials_file})" && exit 1)
        fi
        touch "${storage_credentials_file}" || (__log 'ERROR' "Unable to create file: ${storage_credentials_file}" && exit 1)
    fi

    cmd_create_customer_secret_keys="${OCI} iam customer-secret-key create --user-id ${ocid_sa_tf} --display-name access_tf_bucket"
    run_oci_command "${cmd_create_customer_secret_keys}" || (__log 'ERROR' "Unable to create customer secret key for ${sa_tf}" && exit 1)
    sa_tf_secret_key=$(cat $tmp_file | jq -r '.data')

    sa_tf_customer_secret_key[aws_access_key_id]=$(cat $tmp_file | jq -r '.data.id')
    sa_tf_customer_secret_key[aws_secret_access_key]=$(cat $tmp_file | jq -r '.data.key')

    if ! update_ini_file sa_tf_customer_secret_key $storage_credentials_file $tmp_file; then
        __log 'ERROR' "Unable to update ${config_file} with ${sa_tf} customer keys" && exit 1
    fi
fi

__log 'SUCCESS' 'Done!' && exit 0