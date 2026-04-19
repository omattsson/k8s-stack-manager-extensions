import unittest
from http.server import HTTPServer
import threading
import requests
import time

# Assume server.py exposes a function to start the server for testing
import server

class TestMaintenanceGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = HTTPServer(('localhost', 8081), server.RequestHandler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever)
        cls.thread.daemon = True
        cls.thread.start()
        time.sleep(0.2)  # Give server time to start

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.thread.join()

    def test_healthz(self):
        resp = requests.get('http://localhost:8081/healthz')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.text, 'ok')

    # Add more tests for signature verification and gate logic as needed.

if __name__ == '__main__':
    unittest.main()
