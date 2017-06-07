import csv
import re
from netaddr import IPNetwork
import os
import argparse

rules_in_shared_secgroup = [
    'data-mongod',
    'dim-mongos',
    'dwh-mongod',
    'psm-kafka',
    'release-dbscript',
    'troubleshoot-dbscript'
]


def parse_rules_from_csv(csv_file):
    rules = []
    with open(csv_file, 'r') as csv_sg:
        sg_rules = csv.reader(csv_sg, delimiter=',')
        for rule in sg_rules:
            if (
                (not rule[0] in rules_in_shared_secgroup) and
                (not rule[1] in rules_in_shared_secgroup)
            ):
                rules.append(rule)
    return rules


def populate_groups(rules):
    groups = []
    ips = []
    sg_ids = []
    invalid_input = []
    for rule in rules:
        if (is_cidr(rule[0])):
            ips.append(rule[0])
        elif (is_sg_id(rule[0])):
            sg_ids.append(rule[0])
        elif is_group_name(rule[0]):
            groups.append(rule[0])
        else:
            invalid_input.append(rule[0])
        if (is_cidr(rule[1])):
            ips.append(rule[1])
        elif (is_sg_id(rule[1])):
            sg_ids.append(rule[1])
        elif is_group_name(rule[1]):
            groups.append(rule[1])
        else:
            invalid_input.append(rule[1])
    seen = set()
    groups_filtered = [
        item for item in groups if item not in seen and not seen.add(item)]
    return groups_filtered, ips, sg_ids, invalid_input


def is_group_name(sg):
    pattern = re.compile(r"^(?!sg|[0-9])^[a-zA-Z0-9-]{1,255}")
    try:
        match_group = re.findall(pattern, sg)
        if (len(match_group[0]) == len(sg)):
            return True
        else:
            return False
    except:
        return False


def is_sg_id(sg):
    pattern = re.compile(r"(sg-)([a-z0-9]{8})")
    try:
        match_sg_id = re.match(pattern, sg)
        if len(match_sg_id.group()) > 0:
            if len(sg) == 11:
                return True
            else:
                return False
        else:
            return False
    except:
        return False


def is_cidr(ip):
    try:
        ip = IPNetwork(ip)
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
        count_sg_ids = []
        groups = []
        for rule in rules:
            if [rule[2], rule[3], rule[4]] == port:
                groups.append(rule)
                if (direction == "in"):
                    if(is_cidr(rule[0])):
                        count_ips.append(rule)
                    if(is_sg_id(rule[0])):
                        count_sg_ids.append(rule)
                if (direction == "out"):
                    if(is_cidr(rule[1])):
                        count_ips.append(rule)
                    if(is_sg_id(rule[1])):
                        count_sg_ids.append(rule)
        groups = [x for x in groups if (x not in count_ips)]
        groups = [x for x in groups if (x not in count_sg_ids)]

        new_rules = True
        if len(groups) > 0:
            new_rules = False
            print("\t- group_names:").expandtabs(2)
            for rule in groups:
                if direction == "in":
                    col = rule[0]
                elif direction == "out":
                    col = rule[1]
                print("\t\t\t- %s" % (col)).expandtabs(2)

        if len(count_sg_ids) > 0:
            if new_rules:
                new_rules = False
                print("\t- group_ids:").expandtabs(2)
            else:
                print("\t\tgroup_ids:").expandtabs(2)
            for rule in count_sg_ids:
                if direction == "in":
                    col = rule[0]
                elif direction == "out":
                    col = rule[1]
                print("\t\t\t- %s" % (col)).expandtabs(2)

        if(len(count_ips) > 0):
            if new_rules:
                new_rules = False
                print("\t- cidr_ips:").expandtabs(2)
            else:
                print("\t\tcidr_ips").expandtabs(2)
            for rule in count_ips:
                if direction == "in":
                    col = rule[0]
                elif direction == "out":
                    col = rule[1]
                print("\t\t\t- '%s'" % (col)).expandtabs(2)
        print("\t\trules:").expandtabs(2)
        print("\t\t\t- from_port: %s" % port[0]).expandtabs(2)
        print("\t\t\t\tto_port: %s" % port[1]).expandtabs(2)
        print("\t\t\t\tproto: \"%s\"" % port[2]).expandtabs(2)
    print ""


def print_related_secgroup(group, rules):
    print("related secgroup:")
    for rule in rules:
        if group == rule[0] and not is_cidr(rule[1]):
            print("\t- %s" % rule[1]).expandtabs(2)
        elif group == rule[1] and not is_cidr(rule[0]):
            print("\t- %s" % rule[0]).expandtabs(2)


def execution_checklists(groups):
    for group in groups:
        print(
            "ansible-playbook playbooks/local_role.yml "
            "-e \"role_name=security_groups/%s "
            "secgroup_vpc_id=vpc-32b41f57\" -vvv --check" % (group))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="""
            Parse related security groups and also ingress-egress from CSV
        """)
    parser.add_argument('--file', help="csv file")
    args = parser.parse_args()

    os.system('clear')
    print("Connectivity Parser")
    print("===================")

    try:
        rules = parse_rules_from_csv(args.file)
    except:
        print("Please define correct filename using --file argument")
        exit(0)

    groups = populate_groups(rules)

    if(len(groups[3]) > 0):
        print("Invalid input detected : ")
        for group in groups[3]:
            print("- %s" % group)
        exit(0)
    else:
        print("\n* List of Connectivity Changes")
        for group in groups[0]:
            print("# %s #" % (group)).expandtabs(2)
            print_related_secgroup(group, rules)
            print ""
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
        for group in groups[0]:
            print("\t- %s" % (group)).expandtabs(2)
        print("\n* Execute Playbook")
        execution_checklists(groups[0])
