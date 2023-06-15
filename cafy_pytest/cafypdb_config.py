class CafyPdb_Configs:
    Webex_Notification_Url = 'https://cafy3.cisco.com:3500/api/notifications/sns/cafypdb'
    API_KEY = 'f912594816b83760756f3cfdcb32f08bdf3f9b6fe46183323ec0aaf0e4afe25b '
    connection_timeout = 7200
   
    @staticmethod
    def get_webex_url():
        """
        return Webex_Notification_Url
        """
        return CafyPdb_Configs.Webex_Notification_Url
    
    @staticmethod
    def get_api_key():
        """
        return Api Key 
        """
        return CafyPdb_Configs.API_KEY

    @staticmethod
    def get_connection_timeout():
        """
        return connection time out in sec(2hr = 7200 sec)
        """
        return CafyPdb_Configs.connection_timeout

