
#db tests

import unittest
from unittest.mock import MagicMock
from db import DB
class TestYourClass(unittest.TestCase):

    def setUp(self):
        # Assuming YourClass has a connection to a MongoDB database
        # You can use MagicMock to mock the database connection
        self.mock_db = MagicMock()
        self.dbinst = DB(self.mock_db)

    def test_is_account_exist_returns_true(self):
        # Mock the find method of the database to return a non-empty cursor
        self.mock_db.accounts.find.return_value = [{'username': 'karim'}]

        # Call the method you want to test
        result = self.dbinst.is_account_exist('karim')

        # Assert that the result is True since the account exists
        self.assertTrue(result)

    def test_is_account_exist_returns_false(self):
        # Mock the find method of the database to return an empty cursor
        self.mock_db.accounts.find.return_value = []

        # Call the method you want to test
        result = self.dbinst.is_account_online('non_existing_user')

        # Assert that the result is False since the account does not exist
        self.assertFalse(result)


    def test_is_account_online_returns_true(self):
        # Mock the find method of the database to return a non-empty cursor
        self.mock_db.online_peers.find.return_value = [{'username': 'karim'}]

        # Call the method you want to test
        result = self.dbinst.is_account_online('karim')

        # Assert that the result is True since the account exists
        self.assertTrue(result)

    def test_is_account_online_returns_false(self):
        # Mock the find method of the database to return an empty cursor
        self.mock_db.online_peers.find.return_value = []

        # Call the method you want to test
        result = self.dbinst.is_account_exist('non_existing_user')

        # Assert that the result is False since the account does not exist
        self.assertFalse(result)

    def test_register(self):
        # Input data
        username = "test_user"
        password = "test_password"
        salt = "test_salt"

        # Call the method you want to test
        self.dbinst.register(username, password, salt)

        # Assert that insert_one was called with the expected arguments
        expected_account = {
            "username": username,
            "password": password,
            "salt": salt
        }
        if(self.dbinst.get_password(username)): res = True
        else : res =False
        self.assertTrue(res)
    def test_get_host_ip_udp_port_existing_group(self):
        # Call the method you want to test
        result = self.dbinst.get_host_ip_udp_port("group")
        # Assert that the result is the expected tuple
        self.assertEqual(result, ("192.168.1.3", "60441"))
    def test_get_password(self):
        # Input data
        username = "test_user"
        expected_password = "test_password"
        # Call the method you want to test
        result = self.dbinst.get_password(username)
        # Assert that the result matches the expected password
        self.assertEqual(result, expected_password)
    def test_get_salt(self):
        # Input data
        username = "test_user"
        expected_salt = "test_salt"

        # Call the method you want to test
        result = self.dbinst.get_salt(username)

        # Assert that the result matches the expected salt
        self.assertEqual(result, expected_salt)


    def test_get_online_peers(self):
        # Mock the return value of the find method
        online_peers_data = [{"karim": "1234"},{"mina": "12345678m"}]
        self.mock_db.online_peers.find.return_value = online_peers_data

        # Call the method you want to test
        result = self.dbinst.get_online_peers()

        # Assert that the result matches the expected list of usernames
        expected_usernames = ["karim","mina"]
        self.assertEqual(result, expected_usernames)

    def test_get_groups(self):
        # Mock the return value of the find method
        groups_data = [{"group_name": "group"}]


        # Call the method you want to test
        result = self.dbinst.get_groups()

        expected_group_names = ["group"]
        self.assertEqual(result, expected_group_names)
    def test_user_login(self):
        # Input data
        username = "test_user"
        ip = "127.0.0.1"
        port = 12345
        udp_port = 54321

        # Call the method you want to test
        self.dbinst.user_login(username, ip, port, udp_port)
        peers = self.dbinst.get_online_peers()
        if(username in peers): result = True
        else: result = False
        # Assert that insert_one was called with the expected arguments
        self.assertTrue(result)

    def test_user_logout(self):
        # Input data
        username = "test_user"

        # Call the method you want to test
        self.dbinst.user_logout(username)
        peers = self.dbinst.get_online_peers()
        if(username in peers): result = True
        else: result = False
        self.assertFalse(result)

    def test_is_group_exists_returns_false(self):

        result = self.dbinst.is_group_exists("gr")
        print(result)
        # Assert that the result is False since the account does not exist
        self.assertFalse(result)




    def test_add_group(self):
        # Call the method you want to test
        self.dbinst.add_group("test_group", "test_host")
        gr = self.dbinst.get_groups()
        if("test_group" in gr):result = True
        else: result = False

        self.assertTrue(result)
    def test_is_group_exists_returns_true(self):

        result = self.dbinst.is_group_exists("group")
        # Assert that the result is False since the account does not exist
        self.assertTrue(result)

    def test_add_peer_in_group(self):
        # Call the method you want to test
        self.dbinst.add_peer_in_group("test_group", "test_user")
        res = self.dbinst.get_last_peer_in_group("test_group")
        if(res == "test_user"):result = True
        else:result = False

        self.assertTrue(result)

    def test_find_user_in_groups_existing_user(self):
        # Call the method you want to test
        result = self.dbinst.find_user_in_groups("karim")
        # Assert that the result is the expected list of group names
        self.assertEqual(result, ["group"])
    def test_count_members_in_group_existing_group(self):
        # Call the method you want to test
        result = self.dbinst.count_members_in_group("test_group")
        # Assert that the result is the expected count of members
        self.assertEqual(result, 2)

    def test_update_group_host_existing_group(self):

        # Call the method you want to test
        self.dbinst.update_group_host("group", "karim")
        res = self.dbinst.get_host_ip_udp_port("test_group")
        found = self.dbinst.get_online_peers()
        if("karim" in found):result = True
        else: result = False
        self.assertTrue(result)



    def test_get_peer_before_in_group(self):
        # Call the method you want to test with the first peer as an argument
        result = self.dbinst.get_peer_before_in_group("group", "karim")

        # Assert that the result is None since there is no peer before the first peer
        self.assertEqual(result,"mina")
    def test_get_peer_after_in_group(self):
        # Call the method you want to test with the first peer as an argument
        result = self.dbinst.get_peer_after_in_group("group", "mina")

        # Assert that the result is None since there is no peer before the first peer
        self.assertEqual(result,"karim")
    def test_get_last_peer_in_group(self):

        # Call the method you want to test
        result = self.dbinst.get_last_peer_in_group("group")
        # Assert that the result is the last member of the group
        self.assertEqual(result, "karim")


    def test_remove_last_from_group(self):

        # Call the method you want to test
        self.dbinst.remove_last_from_group("test_group")
        # Assert that update_one was called with the expected arguments
        res = self.dbinst.get_last_peer_in_group("test_group")
        if(res != "test_user"): result = True
        else: result = False
        self.assertTrue(result)

    def test_remove_peer_from_group(self):
        # Call the method you want to test
        self.dbinst.remove_peer_from_group("test_group", "test_host")

        cnt = self.dbinst.count_members_in_group("test_group")
        if(cnt == 0):result=True
        else: result = False
        self.assertTrue(result)

    def test_delete_group(self):
        # Mock the return value of find_one to simulate a non-existing group
        self.mock_db.groups.find_one.return_value = None

        # Call the method you want to test
        self.dbinst.delete_group("test_group")
        gr = self.dbinst.get_groups()
        if("test_group" in gr):result = True
        else: result = False
        self.assertFalse(result)




if __name__ == "__main__":
    unittest.main()
