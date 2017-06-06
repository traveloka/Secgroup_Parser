import csv
import re
common_rules = ['office_ip_vpn']
rules_in_shared_secgroup = ['data-mongod','dim-mongos','dwh-mongod','psm-kafka','release-dbscript','troubleshoot-dbscript']

def parse_rules_from_csv(csv_file):
    rules = []
    with open(csv_file, 'r') as csv_sg:
        sg_rules = csv.reader(csv_sg, delimiter=',')
        for rule in sg_rules:
            if not rule[0] in rules_in_shared_secgroup or not rule[1] in rules_in_shared_secgroup:
               rules.append(rule)
    return rules


def populate_groups(rules):
    groups = []
    for rule in rules:
        if (
            (rule[0] not in groups) and
            (rule[0] not in common_rules) and
            (is_cidr(rule[0]) is False)
        ):
            groups.append(rule[0])
        if (
            (rule[1] not in groups) and
            (rule[1] not in common_rules) and
            (is_cidr(rule[0]) is False)
        ):
            groups.append(rule[1])
    return groups


def is_cidr(ip):
    pattern = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?")
    try:
        match_cidr = re.match(pattern, ip)
        if len(match_cidr.group()) > 0:
            return True
    except:
        return False


def parse_rules(direction, group_name, rules):
    parsed = []
    for rule in rules:
        if (direction == "in"):
            col = rule[1]
        elif (direction == "out"):
            col = rule[0]
        if (col == group):
            parsed.append(rule)
    return parsed


def print_rules(direction, rules):
    ports = []
    for rule in rules:
        if [rule[2], rule[3], rule[4]] not in ports:
            ports.append([rule[2], rule[3], rule[4]])
    for port in ports:
        count_ips = []
        groups = []
        for rule in rules:
            if [rule[2], rule[3], rule[4]] == port:
                groups.append(rule)
                if (direction == "in"):
                    if(is_cidr(rule[0])):
                        count_ips.append(rule)
                if (direction == "out"):
                    if(is_cidr(rule[1])):
                        count_ips.append(rule)
        groups = [x for x in groups if (x not in count_ips)]
        print("\t- group_names:").expandtabs(2)
        for rule in groups:
            if direction == "in":
                col = rule[0]
            elif direction == "out":
                col = rule[1]
            print("\t\t\t- %s" % (col)).expandtabs(2)
        if(len(count_ips) > 0):
            print("\t\tcidr_ips:").expandtabs(2)
            for rule in count_ips:
                if direction == "in":
                    col = rule[0]
                elif direction == "out":
                    col = rule[1]
                print("\t\t\t- '%s'" % (col)).expandtabs(2)
        print("\t\trules:").expandtabs(2)
        print("\t\t\t- from: %s" % port[0]).expandtabs(2)
        print("\t\t\t\tto: %s" % port[1]).expandtabs(2)
        print("\t\t\t\tproto: %s" % port[2]).expandtabs(2)


def execution_checklists(groups):
    for group in groups:
        print(
            "ansible-playbook playbooks/local_role.yml "
            "-e \"role_name=security_groups/%s "
            "secgroup_vpc_id=vpc-32b41f57\" -vvv --check" % (group))


if __name__ == '__main__':
    print("Connectivity Parser")
    print("===================")

    rules = parse_rules_from_csv('sg_rules.csv')

    groups = populate_groups(rules)

    print("\n* List of Connectivity Changes")
    for group in groups:
        print("\n%s" % (group)).expandtabs(2)
        print("===")
        egress_rules = parse_rules("out", group, rules)
        ingress_rules = parse_rules("in", group, rules)
        if (len(ingress_rules) > 0):
            print("secgroup_ingress_acls:").expandtabs(2)
            print_rules("in", ingress_rules)

        if (len(egress_rules) > 0):
            print("secgroup_egress_acls:").expandtabs(2)
            print_rules("out", egress_rules)

    print("\nExecution Checklist")
    print("===================")
    print("\n* Security Groups Needs to Update")
    for group in groups:
        print("\t- %s" % (group)).expandtabs(2)
    print("\n* Execute Playbook")
    execution_checklists(groups)
