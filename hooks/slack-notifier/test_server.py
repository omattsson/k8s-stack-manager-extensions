import unittest
from http.server import HTTPServer
import threading
import requests
import time
import server

class TestSlackNotifier(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = HTTPServer(('localhost', 8082), server.SlackNotifierHandler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever)
        cls.thread.daemon = True
        cls.thread.start()
        time.sleep(0.2)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.thread.join()

    def test_healthz(self):
        resp = requests.get('http://localhost:8082/healthz')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.text, 'ok')

    # Add more tests for signature verification and notification logic as needed.

if __name__ == '__main__':
    unittest.main()
