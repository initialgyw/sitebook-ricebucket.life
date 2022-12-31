#!/usr/bin/env bash
<<COMMENT
Secures the root Oracle cloud account with MFA.
COMMENT

set -o errexit    # exit if command fails
set -o nounset    # exit if variables are unset
set -o pipefail   # exit if pipe commands fail

# source common functions
SCRIPTPATH=$(cd -- $(dirname $0) > /dev/null 2>&1; pwd -P)
source ${SCRIPTPATH}/common.sh

function usage() {
    echo "Usage: $(basename $0)"
    echo '  -h | --help        Show this menu'
    echo '  -r | --region      REQUIRED[str]: Primary region for the OCI account'
    echo '  -t | --tenancy     REQUIRED[str]: Tenancy name for the OCI account'
    echo '  -c | --config-file OPTIONAL[str]: Provide the location of the configuration file. Defaults = ~/.oci/config'
    echo '  -p | --profile     OPTIONAL[str]: Profile name for the configuration. If not provided, it will be set to Tenancy name'
    echo '  -v | --verbose     OPTIONAL[bool]: Set logging to DEBUG. Default = INFO'
}

OPTIONS=$(getopt -o hvt:r:p:c: --long help,verbose,tenancy:,region:,profile:,config-file: -n 'secure-oci-account.sh' -- "$@")
[ $? != 0 ] && usage >&2 && exit 1
eval set -- "$OPTIONS"

# setting initial variables
profile=
region=
tenancy=
script_log_level='INFO'
config_file="${HOME}/.oci/config"
tmp_file="/tmp/$(basename $0)"

[ $# -le 1 ] && __log 'ERROR' 'No options provided' && usage && exit 1
while true; do
    case "$1" in
        -h | --help) usage && exit 0 ;;
        -v | --verbose) script_log_level='DEBUG'; shift ;;
        -r | --region) region="$2"; shift 2 ;;
        -t | --tenancy) tenancy="$2"; shift 2 ;;
        -p | --profile) profile="$2"; shift 2 ;;
        -c | --config-file) config_file="$2"; shift 2 ;;
        --) shift; break ;;
        *) log 'ERROR' "Unknown option: ${1}" && usage && exit 1 ;;
  esac
done

# script requirements
required_apps=(oci oathtool)
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

# ########################
# Script tasks starts here
# ########################

source ${SCRIPTPATH}/oci.sh

# check for valid token
cmd_check_valid_session="oci session validate"
cmd_check_valid_session+=" --profile ${profile} --config-file ${config_file} --region ${region} --local"

cmd_session_authenticate="oci session authenticate"
cmd_session_authenticate+=" --config-location ${config_file} --profile-name ${profile} --region ${region} --tenancy-name ${tenancy}"

run_oci_command "${cmd_check_valid_session}" || (run_oci_command "${cmd_session_authenticate}" && run_oci_command "${cmd_check_valid_session}")
__log 'DEBUG' "Current session is valid."

# get all users in account
cmd_get_users="${OCI} iam user list"
if ! run_oci_command "${cmd_get_users}"; then
    __log 'ERROR' 'Unable to get list of users. Are you an Administrator?' && exit 1
fi
users=$(cat $tmp_file)

# get account info
ocid_tenancy=$(echo "${users}" | jq -r '.data[0]."compartment-id"')
user_account_name=$(echo "${users}" | jq -r '.data[0].name')
ocid_user_account=$(echo "${users}" | jq -r '.data[0].id')
user_account_mfa_status=$(echo "${users}" | jq -r '.data[0]."is-mfa-activated"')

__log 'DEBUG' "VAR ocid_tenancy = ${ocid_tenancy}"
__log 'DEBUG' "VAR user_account_name = ${user_account_name}"
__log 'DEBUG' "VAR ocid_user_account = ${ocid_user_account}"
__log 'DEBUG' "VAR user_account_mfa_status = ${user_account_mfa_status}"

[[ "${user_account_mfa_status}" == 'true' ]] && __log 'INFO' "MFA is already enabled for ${user_account_name}" && exit 0

# MFA status is false, will create
__log 'INFO' "${user_account_name} MFA is not enable. Will enable it."

# get totp devices
cmd_get_user_totp_devices="${OCI} iam mfa-totp-device list --user-id ${ocid_user_account}"
run_oci_command "${cmd_get_user_totp_devices}" || (__log 'CRITICAL' "Failed to get list of totp devices for ${user_account_name}" && exit 1)
user_totp_devices=$(cat $tmp_file)

# if no totp device exists, create it
if [ -z "${user_totp_devices}" ]; then
    __log 'INFO' "No TOTP device found in ${user_account_name} account. Will create."
    cmd_create_totp_device="${OCI} iam mfa-totp-device create --user-id ${ocid_user_account}"
    run_oci_command "${cmd_create_totp_device}" ] || (__log 'CRITICAL' "Failed to create TOTP device for ${user_account_name}" && exit 1)

    ocid_user_totp_device=$(cat $tmp_file | jq -r '.data.id')  
    ocid_user_totp_device_status=$(cat $tmp_file | jq -r '.data."is-activated"')
    ocid_user_totp_device_seed=$(cat $tmp_file | jq -r .'data.seed')
    __log 'SUCCESS' "Successfully created TOTP Device for ${user_account_name}: ${ocid_user_totp_device}"
else
    __log 'INFO' "TOTP device already exists for user ${ocid_user_account}"

    # you can only have one totp device so statically settiing to 0 is fine
    ocid_user_totp_device=$(echo "$user_totp_devices" | jq -r '.data[0].id')
    ocid_user_totp_device_status=$(echo "$user_totp_devices" | jq -r '.data[0]."is-activated"')
    ocid_user_totp_device_seed=$(echo "$user_totp_devices" | jq -r .'data[0].seed')
fi
__log 'DEBUG' "VAR ocid_user_totp_device = $ocid_user_totp_device"
__log 'DEBUG' "VAR ocid_user_totp_device_status = $ocid_user_totp_device_status"
__log 'DEBUG' "VAR ocid_user_totp_device_seed = $ocid_user_totp_device_seed"

# Enable TOTP Device
if [[ "${ocid_user_totp_device_status}" == 'false' ]]; then
    __log 'INFO' "TOTP device is not active. Will activate."
    cmd_generate_totp_seed="${OCI} iam mfa-totp-device generate-totp-seed"
    cmd_generate_totp_seed+=" --user-id ${ocid_user_account} --mfa-totp-device-id ${ocid_user_totp_device}"
    run_oci_command "${cmd_generate_totp_seed}" || (__log 'CRITICAL' "Unable to generate a TOTP seed for ${ocid_user_account} TOTP device" && exit 1)
    
    totp_seed=$(cat $tmp_file | jq -r '.data.seed')

    RED=$(tput setaf 1)
    NORMAL=$(tput sgr0)
    printf "${RED}%55s${NORMAL}\n" | tr ' ' \*
    printf "${RED}SAVE THIS SECRET SEED: ${totp_seed}${NORMAL}\n"
    printf "${RED}%55s${NORMAL}\n" | tr ' ' \*

    # activate the totp device
    totp_token=$(oathtool --base32 --totp $totp_seed)
    cmd_activate_totp_device="${OCI} iam mfa-totp-device activate"
    cmd_activate_totp_device+=" --user-id ${ocid_user_account} --mfa-totp-device-id ${ocid_user_totp_device} --totp-token ${totp_token}"
    run_oci_command "${cmd_activate_totp_device}" || (__log 'CRITICAL' 'Unable to activate TOTP device' && exit 1)
    __log 'SUCCESS' "Successfully activated TOTP device for ${ocid_user_account}"
else
    msg="TOTP device active status is set to ${ocid_user_totp_device_status} for ${ocid_user_account}"
    msg+=" Unknown reason why MFA for ${ocid_user_account} is set to ${ocid_user_totp_device_status} (ocid_user_totp_device_status)"
    __log 'ERROR' "${msg}" && exit 1
fi

__log 'INFO' 'DONE.'