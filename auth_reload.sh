####################################
#                                  #
#   Author : Krushi Vasani         #
#                                  #
####################################

#!/bin/sh
vault login -method=okta username=$USER
sft login
echo "#example : class id:edu13000    class size:15"
read -p "class id: " class_id
read -p "class size: " class_size
read -p "Do you want to add Starting Point? (y/n) " answer
case ${answer:0:1} in
    y|Y )
        read -p "Enter Starting Point: " start_point
    ;;
    * )
        start_point=1
    ;;
esac

# for instructor sh and idm
echo "$class_id-instructor"
instructor_stack=$(nslookup sh1.$class_id-instructor.splunkcloud.com | awk '{print $1}' | grep ".-i-" | awk -F. '{print $2}')
PASS=$(vault kv get cloud-sec/std/lve/stacks/$instructor_stack/admin | grep plaintext | awk {'print $2'});
instructor_sh_fqdn=$(nslookup sh1.$class_id-instructor.splunkcloud.com | awk '{print $1}' | grep ".-i-" | awk -F. '{print $1}')
ssh $instructor_sh_fqdn << EOF
    echo $instructor_sh_fqdn
    sudo puppet agent -t  > /dev/null
    echo "Puppet ran successfully"
    sudo su - splunk
    splunk reload auth -auth 'admin:$PASS'
    exit > /dev/null
    exit > /dev/null
EOF
instructor_idm_fqdn=$(nslookup idm1.$class_id-instructor.splunkcloud.com | awk '{print $1}' | grep ".-i-"  | awk -F. '{print $1}')
ssh $instructor_idm_fqdn << EOF
    echo $instructor_idm_fqdn
    sudo puppet agent -t  > /dev/null
    echo "Puppet ran successfully"
    sudo su - splunk 
    splunk reload auth -auth 'admin:$PASS'
    exit > /dev/null
    exit > /dev/null
EOF

# for class size sh and idm 

for i in $(seq $start_point $class_size)
do 
    xpad=$(printf '%02d' $i)
    echo $class_id-$xpad
    STACK_NAME=$(nslookup sh1.$class_id-$xpad.splunkcloud.com | awk '{print $1}' | grep ".-i-" | awk -F. '{print $2}')
    PASS=$(vault kv get cloud-sec/std/lve/stacks/$STACK_NAME/admin | grep plaintext | awk {'print $2'});

    SH1=$(nslookup sh1.$class_id-$xpad.splunkcloud.com | awk '{print $1}' | grep ".-i-"  | awk -F. '{print $1}')
    ssh $SH1 << EOF
    echo $SH1
    sudo puppet agent -t  > /dev/null
    echo "Puppet ran successfully"
    sudo su - splunk 
    splunk reload auth -auth 'admin:$PASS'
    exit > /dev/null
    exit > /dev/null
EOF
    IDM1=$(nslookup idm1.$class_id-$xpad.splunkcloud.com | awk '{print $1}' | grep ".-i-"  | awk -F. '{print $1}')
    ssh $IDM1 << EOF
    echo $IDM1
    sudo puppet agent -t  > /dev/null
    echo "Puppet ran successfully"
    sudo su - splunk 
    splunk reload auth -auth 'admin:$PASS'
    exit > /dev/null
    exit > /dev/null
EOF
done





