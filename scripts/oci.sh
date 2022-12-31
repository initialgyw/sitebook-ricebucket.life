# check if logging exists
if [[ $(type -t __log) != function ]]; then
    # source common functions
    SCRIPTPATH=$(cd -- $(dirname $0) > /dev/null 2>&1; pwd -P)
    source ${SCRIPTPATH}/common.sh
fi

# script requirements

required_apps=(jq openssl)
for app in ${required_apps[@]}; do
    if ! check_required_app "${app}"; then
        __log 'ERROR' "App not installed or in PATH: ${app}" && exit 1
    else
        __log 'DEBUG' "App detected in PATH: ${app}"
    fi
done

# variable validation
if [ -z "${tmp_file-}" ]; then
    tmp_file="/tmp/$(basename $0 | sed 's/$/.tmp/g')"
fi

# ensure the following variables are set
required_vars=(OCI)
for var in ${required_vars[@]}; do
    check_var $var || return 1
done

# get error message
function get_command_error() {
    if cat $tmp_file | grep 'ServiceError:' > /dev/null; then
        cat $tmp_file | egrep -v 'ServiceError' | jq -r '.message'
    else
        cat $tmp_file | grep -i Error
    fi
}

function run_oci_command() {
    local oci_cmd="${1}"
    __log 'DEBUG' "RUNNING -- ${oci_cmd}"

    $oci_cmd > $tmp_file 2>&1
    if [ $? -ne 0 ]; then
        __log 'CRITICAL' "Running ${oci_cmd} returned exit code of $?: $(get_command_error)"
        return 1
    else
        if grep -i error $tmp_file; then
            __log 'CRITICAL' "Running ${oci_cmd} returned exit code of $? BUT: $(get_command_error)"
            return 1
        fi
        #__log 'DEBUG' "$(cat $tmp_file)"
        return 0
    fi
}

# updates a user's capability
function update_user_capabilities() {
    local ocid_user=$1
    local user_caps=$2
    local -n update_caps=$3

    update_capabilities=''
    for cap in ${!update_caps[@]}; do    
        if [[ $(echo "${user_caps}" | jq -r --arg CAP "${cap}" '.[$CAP]') != ${update_caps[$cap]} ]]; then
            update_capabilities="${update_capabilities} --${cap} ${update_caps[$cap]}"
        fi
    done

    [ -z "${update_capabilities}" ] && __log 'DEBUG' "${ocid_user} already have required capabilities" && return 0
    __log 'DEBUG' "Capabilities to update: ${update_capabilities}"

    local cmd_update_caps="${OCI} iam user update-user-capabilities --user-id ${ocid_user} ${update_capabilities}"
    run_oci_command "${cmd_update_caps}" || return 1
    __log 'SUCCESS' "Successfully updated capabilities for ${ocid_user}"

    return 0
}

#
# Generating RSA keys for API
#
function generate_private_rsa_api_key() {
    local __private_api_key_path=$1
    local __passphrase=${2-}

    if [ -f $__private_api_key_path ]; then
        mv $__private_api_key_path ${__private_api_key_path}.backup || (__log 'ERROR' "Unable to move $__private_api_key_path to ${__private_api_key_path}.backup" && return 2)
    fi

    if [ ! -z $__passphrase ]; then
        local cmd_key_gen="openssl genrsa -out ${__private_api_key_path} -aes256 4096"
    else
        local cmd_key_gen="openssl genrsa -out ${__private_api_key_path} 4096"
    fi
    __log 'DEBUG' "RUNNING -- ${cmd_key_gen}"


    $cmd_key_gen > $tmp_file 2>&1
    [ $? -ne 0 ] && __log 'ERROR' "RUNNING ${cmd_key_gen} returned exit code of $?: $(get_command_error)" && return 1
    
    __log 'SUCCESS' "${__private_api_key_path} generated."
    
    return 0
}

function generate_public_rsa_api_key() {
    local __private_api_key_path=$1
    local __public_api_key_path=$2

    [ ! -f $__private_api_key_path ] && __log 'ERROR' "${__private_api_key_path} does not exist." && return 1
    if [ -f ${__public_api_key_path} ]; then
        mv $__public_api_key_path ${__public_api_key_path}.backup || __log 'ERROR' "Unable to move ${__public_api_key_path} to ${__public_api_key_path}.backup" && return 1
        __log 'INFO' "Moved current ${__public_api_key_path} to ${__public_api_key_path}.backup"
    fi

    local cmd_key_gen="openssl rsa -pubout -in ${__private_api_key_path} -out ${__public_api_key_path}"
    __log 'INFO' "DEBUG -- ${cmd_key_gen}"
    $cmd_key_gen > $tmp_file 2>&1
    [ $? -ne 0 ] && __log 'ERROR' "RUNNING ${cmd_key_gen} returned exit code of $?: $(get_command_error)" && return 1
    __log 'SUCCESS' "${__public_api_key_path} generated from ${__private_api_key_path}."

    return 0
}

function get_rsa_key_md5() {
    # https://docs.oracle.com/en-us/iaas/Content/API/Concepts/apisigningkey.htm#four
    local __private_key_path="${1}"

    openssl rsa -pubout -outform DER -in ${__private_key_path} > $tmp_file
    [ $? -ne 0 ] && __log 'ERROR' "Failed to convert ${__private_key_path} to DER format" && return 1

    local cmd_key_md5="openssl md5 -c $tmp_file"
    local md5=$($cmd_key_md5)
    [ $? -ne 0 ] && __log 'ERROR' "RUNNING ${cmd_key_md5} returned exit code of $?: $(get_command_error)" && return 1

    echo $md5 > $tmp_file
    __log 'DEBUG' "MD5 of ${__private_key_path} = $(cat $tmp_file)"
    return 0
}

function update_file_permission() {
    local __file="$1"

    local __update_file_permission=0
    if [[ $(uname) == 'Darwin' ]]; then
        [[ $(stat -f %A $__file) != '600' ]] && __update_file_permission=1
    else
        [[ $(stat -c %a $__file) != '600' ]] && __update_file_permission=1
    fi

    if [ $__update_file_permission -eq 1 ]; then
        oci setup repair-file-permissions --file $__file || (__log 'ERROR' "Unable to update permission for ${__file}" && return 1)
        __log 'DEBUG' "${__file} permission update."
    else
        __log 'DEBUG' "${__file} permission does not need updating"
    fi

    return 0
}