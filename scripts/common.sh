# Check for required app in path
check_required_app() {
    local app="${1}"
    [ -z $(which ${app}) ] && return 1 || return 0
}

# check for required apps in PATH if sourced
if ! check_required_app jq; then
    echo 'ERROR: jq is required for logging' && exit 1
fi

# check for required variable is set
check_vars() {
    local vars=("$@")
    local return_code=0

    for var in "${vars[@]}"; do
        if [ -z "${!var-}" ]; then
            __log 'ERROR' "Variable ${arg} is returned"
            return_code=1
        fi
    done

    return $return_code
}

function check_var() {
    local __var=$1

    [ -z "${!__var-}" ] && __log 'ERROR' "Variable $__var is not set" && return 1

    return 0
}

# requires specific bash version
# https://tldp.org/LDP/abs/html/internalvariables.html
#
function requires_bash_version() {
    local version="${1}"

    if ((BASH_VERSINFO[0] >= ${version})); then
        return 0
    else
        return 1
    fi
}

#
# Logging
#
function __timestamp() {
    date "+%Y%m%dT%H%M%S"
}

function __structured_log() {
    local log_level="${1}"
    local message="${2}"

    message=$(echo "${message}" | sed 's/\\n/\ /g' | tr -s ' ')

    echo '{}' | jq --monochrome-output \
        --compact-output \
        --raw-output \
        --arg timestamp "$(__timestamp)" \
        --arg log_level "${log_level}" \
        --arg message "${message}" \
        '.timestamp=$timestamp|.log_level=$log_level|.message=$message'
}

__log() {
    local log_level="${1}"
    local message="${2}"

    declare -A log_levels=(
        [DEBUG]=0
        [INFO]=1
        [SUCCESS]=2
        [WARN]=3
        [ERROR]=4
        [CRITICAL]=5
    )

    # Set default logging to debug
    # this value should be set from the script
    if [ -z "${script_log_level-}" ]; then
        script_log_level='DEBUG'
    fi

    # check if level exists
    [[ ${log_levels[$log_level]-} ]] || (__log 'CRITICAL' "log_level does not exist: ${log_level}" && exit 1)

    # check if log level is enough to print
    ((${log_levels[$log_level]} < ${log_levels[$script_log_level]})) && return 0

    __structured_log "${log_level}" "${message}"
}

# update INI config
<<COMMENT
Updates an INI configuration with new sections.

The function reads the INI file line by line. If section is detected it will try to update key-values
if it's different from provided associative array.

Parameters
----------
1 : associative array
    must contain name as one of the keys to use used as INI section
2 : str
    path of the INI file
3 : str
    path of the temporary file to store INI configs
COMMENT
function update_ini_file() {
    local -n __data=$1
    local __ini_file=$2
    local __tmp_file=$3

    local __name=${__data[name]}

    # ensure parent directories and file exists
    if [ ! -f $__ini_file ]; then
        parent_dir=$(dirname $__ini_file)
        if [ ! -d ${parent_dir} ]; then
            mkdir -p ${parent_dir} || (__log 'ERROR' "Unable to create $parent_dir" && return 1)
        fi
        touch $__ini_file
    fi

    # if empty ini file
    if [ ! -s $__ini_file ]; then
        echo ${__data[name]} >>$__ini_file
        unset '__data[name]'

        for k in "${!__data[@]}"; do
            echo "${k}=${__data[$k]}" >>$__ini_file
        done
        return 0
    fi

    cat /dev/null >$__tmp_file

    local __start_line_processing=0
    local __line_counter=0
    local __ini_file_total_lines=$(cat $__ini_file | wc -l)

    cat $__ini_file | while read line; do
        __line_counter=$((__line_counter + 1))

        # ignoring blank lines
        [ -z "${line}" ] && continue

        # if processing already and line starts with [, that means it's a new section
        if [ $__start_line_processing -eq 1 ]; then
            if [[ "${line}" == "["*"]" ]]; then
                __start_line_processing=0

                for k in "${!__data[@]}"; do
                    echo "${k}=${__data[$k]}" >>$__tmp_file
                done
            fi
        fi

        # existing section was detected
        if [[ "${line}" == "${__name}" ]]; then
            echo "${line}" >>$__tmp_file
            __start_line_processing=1
            unset '__data[name]'
            continue
        fi

        # not processing any line
        if [ $__start_line_processing -eq 0 ]; then
            if [ $__line_counter -eq $__ini_file_total_lines ]; then
                echo "${line}" >>$__tmp_file

                if [ -v '__data[name]' ]; then
                    echo ${__data[name]} >>$__tmp_file
                    unset '__data[name]'

                    for k in "${!__data[@]}"; do
                        echo "${k}=${__data[$k]}" >>$__tmp_file
                    done
                fi
                continue
            fi

            echo "${line}" >>$__tmp_file
            continue
        fi

        # processing line here
        key=$(echo "${line}" | cut -d= -f1 | xargs)
        value=$(echo "${line}" | cut -d= -f2 | xargs)

        # if key not in associative array, ignore it
        [ "${__data[key]+abc}" ] && continue

        if [[ "${__data[$key]}" == "${value}" ]]; then
            echo "${line}" >>$__tmp_file
        else
            echo "${key}=${__data[$key]}" >>$__tmp_file
        fi
        unset '__data[$key]'
    done

    if ! diff $__ini_file $__tmp_file; then
        local __date=$(date +%Y%m%d%H%M%S)
        local __backup_file="${__ini_file}.backup-${__date}"

        mv ${__ini_file} ${__backup_file} || (__log 'ERROR' "Unable to move $__ini_file to ${__backup_file}" && return 1)
        mv $__tmp_file $__ini_file || (__log 'ERROR' "Unable to move $__tmp_file to $__ini_file" && return 1)
    else
        __log 'DEBUG' "${__name} configuration is already properly set in ${__ini_file}"
    fi

    return 0
}

# get_ini_section
<<COMMENT
Get a section with it's keys and values and save it to a temporary file.

The function reads the INI file line by line. If section is detected, it will get all the key-values
and save it to a temporary file. If section is not detected, it will return 1

Parameters
----------
1 : str
    name of the section to search for
2 : str
    path of the INI file
3 : str
    path of the temporary file to store INI section
COMMENT
function get_ini_section() {
    local __section_name=$1
    local __ini_file=$2
    local __tmp_file=$3

    [ ! -f "${__ini_file}" ] && __log 'ERROR' "${__ini_file} does not exist." && return 1

    cat /dev/null > $__tmp_file
    local __start_line_processing=0

    cat $__ini_file | while read line; do
        if [ $__start_line_processing -eq 1 ] && [[ "${line}" == "["*"]" ]]; then
            __start_line_processing=0
        fi

        if [[ "${line}" == "${__section_name}" ]]; then
            echo "name=${__section_name}" >> $__tmp_file
            __start_line_processing=1
            continue
        fi

        if [ $__start_line_processing -eq 1 ]; then
            key=$(echo "$line" | cut -d= -f1 | xargs)
            value=$(echo "${line}" | cut -d= -f2 | xargs)

            echo "${key}=${value}" >> $__tmp_file
            continue
        fi
    done

    if ! grep -F "name=${__section_name}" $__tmp_file > /dev/null; then
         __log 'ERROR' "Section ${__section_name} not detected in ${__ini_file}" && return 1
    fi

    __log 'DEBUG' "${__section_name} is detected in ${__ini_file}" && return 0
}