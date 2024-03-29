from pymongo import MongoClient


# Includes database operations
class DB:

    # db initializations
    def __init__(self):
        self.client = MongoClient('mongodb://localhost:27017')
        self.db = self.client['p2p-chat']

    # checks if an account with the username exists
    def is_account_exist(self, username):
        cursor = self.db.accounts.find({'username': username})
        doc_count = 0

        for document in cursor:
            doc_count += 1

        if doc_count > 0:
            return True
        else:
            return False

        # if self.db.accounts.find({'username': username}).count() > 0:
        #     return True
        # else:
        #     return False

    # registers a user
    def register(self, username, password, salt):
        account = {
            "username": username,
            "password": password,
            "salt": salt
        }
        self.db.accounts.insert_one(account)

    # retrieves the password for a given username
    def get_password(self, username):
        return self.db.accounts.find_one({"username": username})["password"]

    def get_salt(self, username):
        return self.db.accounts.find_one({"username": username})["salt"]

    # checks if an account with the username online
    def is_account_online(self, username):
        if self.db.online_peers.count_documents({'username': username}) > 0:
            return True
        else:
            return False

    # get a list of all online peers
    def get_online_peers(self):
        online_peers = self.db.online_peers.find()
        #print(len(list(online_peers)))
        #if len(list(online_peers)) == 0: return 0
        names = [peer['username'] for peer in online_peers]
        return names

    # get a list of all groups
    def get_groups(self):
        groups = self.db.groups.find()
        #print(len(list(groups)))
        #if len(list(groups)) == 0: return 0
        group_names = [group['group_name'] for group in groups]
        return group_names

    # logs in the user
    def user_login(self, username, ip, port, udp_port):
        online_peer = {
            "username": username,
            "ip": ip,
            "port": port,
            "udpPort": udp_port
        }
        # self.db.online_peers.insert(online_peer)
        self.db.online_peers.insert_one(online_peer)

    # logs out the user
    def user_logout(self, username):
        # self.db.online_peers.remove({"username": username})
        self.db.online_peers.delete_one({"username": username})

    # retrieves the ip address and the port number of the username
    def get_peer_ip_port(self, username):
        res = self.db.online_peers.find_one({"username": username})
        return (res["ip"], res["port"])

    def get_peer_ip_udp_port(self, username):
        res = self.db.online_peers.find_one({"username": username})
        return (res["ip"], res["udpPort"])

    # checks if the group exists
    def is_group_exists(self, group_name):
        if self.db.groups.count_documents({'group_name': group_name}) > 0:
            return True
        else:
            return False

    def add_group(self, group_name, host):
        group = {
            "group_name": group_name,
            "host": host,
            "members": host
        }
        self.db.groups.insert_one(group)

    def get_last_peer_in_group(self, group_name):
        group_data = self.db.groups.find_one({'group_name': group_name})
        if group_data and 'members' in group_data:
            list_of_members = group_data['members'].split(',')
            return list_of_members[-1] if list_of_members else None
        return None

    def add_peer_in_group(self, group_name, user_name):
        group_data = self.db.groups.find_one({'group_name': group_name})
        if group_data and 'members' in group_data:
            list_of_members = group_data['members'].split(',')
            list_of_members.append(user_name)
            self.db.groups.update_one(
                {'group_name': group_name},
                {'$set': {'members': ','.join(list_of_members)}}
            )

    def get_host_ip_udp_port(self, group_name):
        group_data = self.db.groups.find_one({'group_name': group_name})
        if group_data and 'members' in group_data:
            host_name = group_data['host']
            print("form db " + host_name)
            ret = self.get_peer_ip_udp_port(host_name)
            print("from db ", ret)
            return ret

    def remove_last_from_group(self, group_name):
        group_data = self.db.groups.find_one({'group_name': group_name})
        if group_data and 'members' in group_data:
            list_of_members = group_data['members'].split(',')
            if list_of_members:
                list_of_members.pop()  # Remove the last member
                self.db.groups.update_one(
                    {'group_name': group_name},
                    {'$set': {'members': ','.join(list_of_members)}}
                )

    def get_peer_before_in_group(self, group_name, peer_name):
        group_data = self.db.groups.find_one({'group_name': group_name})

        if group_data and 'members' in group_data:
            list_of_members = group_data['members'].split(',')
            if peer_name in list_of_members:
                index = list_of_members.index(peer_name)
                if index > 0:
                    return list_of_members[index - 1]
        return None

    def get_peer_after_in_group(self, group_name, peer_name):
        group_data = self.db.groups.find_one({'group_name': group_name})

        if group_data and 'members' in group_data:
            list_of_members = group_data['members'].split(',')
            if peer_name in list_of_members:
                index = list_of_members.index(peer_name)
                if index + 1 < len(list_of_members):
                    return list_of_members[index + 1]
        return None

    def remove_peer_from_group(self, group_name, user_to_remove):
        group_data = self.db.groups.find_one({'group_name': group_name})
        if group_data and 'members' in group_data:
            list_of_members = group_data['members'].split(',')
            if user_to_remove in list_of_members:
                list_of_members.remove(user_to_remove)  # Remove the specified user
                self.db.groups.update_one(
                    {'group_name': group_name},
                    {'$set': {'members': ','.join(list_of_members)}}
                )

    def count_members_in_group(self, group_name):
        group_data = self.db.groups.find_one({'group_name': group_name})

        if group_data and 'members' in group_data:
            list_of_members = group_data['members'].split(',')
            count = len(list_of_members)
            return count
        else:
            return 0  # Return 0 if the group doesn't exist or has no members

    def delete_group(self, group_name):
        # Find the group to check if it exists
        group_data = self.db.groups.find_one({'group_name': group_name})

        if group_data:
            # If the group exists, delete it from the database
            self.db.groups.delete_one({'group_name': group_name})
            print(f"Group '{group_name}' deleted successfully.")
        else:
            print(f"Group '{group_name}' not found.")

    def find_user_in_groups(self, user_to_find):
        groups_with_user = []
        all_groups = self.db.groups.find({})  # Retrieve all groups

        for group in all_groups:
            if 'members' in group:
                list_of_members = group['members'].split(',')
                if user_to_find in list_of_members:
                    groups_with_user.append(group['group_name'])

        return groups_with_user

    def update_group_host(self, group_name, new_host):
        filter_query = {"group_name": group_name}
        update_query = {"$set": {"host": new_host}}

        self.db.groups.update_one(filter_query, update_query)

