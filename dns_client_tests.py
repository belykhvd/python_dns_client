import unittest
from unittest.mock import Mock, MagicMock
from binascii import hexlify, unhexlify
from dns_client import *


class UnitTests(unittest.TestCase):
    def setUp(self):        
        self.dns_response_hex = '00 00 81 80 00 01 00 02 00 00 00 00 03 77 77 77 09 68 61 62 72 61 68 61' \
                                ' 62 72 02 72 75 00 00 01 00 01 c0 0c 00 05 00 01 00 00 0e 10 00 02 c0 10' \
                                ' c0 10 00 01 00 01 00 00 0e 10 00 04 b2 f8 ed 44'
        self.dns_response = bytes([int(h, 16) for h in self.dns_response_hex.split()])

    def test_transaction_parser(self):
        actual_transaction = Transaction.parse(self.dns_response)

        expected_flags = Flags(True, '0000', False, False, True, True, False, False, '0000')
        expected_query = ResourceRecord('www.habrahabr.ru', RecordTypes.A, RecordClasses.IN)
        expected_answers = [ResourceRecord('www.habrahabr.ru', RecordTypes.Unknown, RecordClasses.IN, 3600, 2, 'c0 10'),
                            ResourceRecord('habrahabr.ru', RecordTypes.A, RecordClasses.IN, 3600, 4, '178.248.237.68')]
        expected_transaction = Transaction(0, expected_flags, 1, 2, 0, 0,
                                           [expected_query], expected_answers, [], [])

        self.assertEqual(str(actual_transaction), str(expected_transaction))

    def test_encode_name(self):
        domain_names = ('www.yandex.ru', 'yandex.ru.', '.')
        actual_parsed = [encode_name(name) for name in domain_names]
        expected_parsed = [b'\x03www\x06yandex\x02ru\x00', b'\x06yandex\x02ru\x00', b'\x00']
        self.assertEqual(actual_parsed, expected_parsed)

    def test_parse_name(self):
        encoded_name = b'\x03www\x06yandex\x02ru\x00'
        actual_parsed = parse_name(encoded_name)
        expected_parsed = 'www.yandex.ru'
        self.assertEqual(actual_parsed, expected_parsed)

    def test_parse_ip(self):
        ips = (bytes([192, 168, 1, 1]), 
               bytes([32, 1, 13, 184, 17, 163, 9, 215, 31, 52, 138, 46, 7, 160, 118, 93]))
        actual_parsed = (parse_ip_address(ips[0], RecordTypes.A), parse_ip_address(ips[1], RecordTypes.AAAA))
        expected_parsed = ('192.168.1.1', '2001:0db8:11a3:09d7:1f34:8a2e:07a0:765d')
        self.assertEqual(actual_parsed, expected_parsed)

    def test_flags_parser(self):
        flags_bytes = b'\x01\x00'
        actual_parsed = Flags.parse(flags_bytes)
        expected_parsed = Flags(False, '0000', False, False, True, False, False, False, '0000')
        self.assertEqual(str(actual_parsed), str(expected_parsed))

    def test_transaction_bytes_getting(self):
        query = ResourceRecord("www.yandex.ru", RecordTypes.A, RecordClasses.IN)
        transaction = Transaction.default_query_transaction(0, Flags.default_query_flags(), [query])
        transaction_bytes = transaction.bytes()
        expected_bytes = b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06yandex\x02ru\x00\x00\x01\x00\x01'
        self.assertEqual(transaction_bytes, expected_bytes)

    def _read_file(self, filename):
        with open(filename, 'rb') as f:
            return f.read()

    def test_poll_nameservers(self):
        responses_bytes = [self._read_file('1.response'), self._read_file('2.response'), self._read_file('3.response')]
        responses = list(map(lambda r: Result.ok(r), responses_bytes))
        transmission_handler_mock = type('DNSTransmissionHandler', (object,), {'request': Mock(side_effect=responses)})
        domain_name = "www.yandex.ru"
        result = DNSResolver._poll_nameservers(domain_name, RecordTypes.A, transmission_handler_mock)
        expected_result = Result.ok(responses_bytes[2])
        self.assertEqual(result.value, expected_result.value)

    def test_resolve_recursivly(self):
        response = self._read_file('3.response')
        desired_response_result = Result.ok(response)
        dns_transmission_handler = DNSTransmissionHandler()
        dns_transmission_handler.request = MagicMock(return_value=desired_response_result)
        ipv4_result, ipv6_result = DNSResolver.resolve_recursively("www.yandex.ru", dns_transmission_handler)
        expected_ip4_result = Result.ok(response)
        self.assertEqual(ipv4_result.value, expected_ip4_result.value)

    def test_correct_printing(self):
        query = ResourceRecord("www.yandex.ru", RecordTypes.A, RecordClasses.IN)
        ok_transaction = Transaction.default_query_transaction(0, Flags.default_query_flags(), [query])
        output_format = 'RAW'
        ipv4_output = printable_response(ok_transaction.bytes(), output_format)
        expected_output = '00 00 01 00 00 01 00 00 00 00 00 00 03 77 77 77 06 79 61 6e 64 65 78 02 72 75 00 00 01 00 01'
        self.assertEqual(ipv4_output, expected_output)

    def test_connection_info(self):
        ip, port, transmission_protocol, receive_timeout = '8.8.8.8', 53, socket.SOCK_STREAM, 2
        connection_info = ConnectionInfo(ip, port, transmission_protocol, receive_timeout)
        with connection_info.configure_socket() as sock:
            destination = connection_info.get_destination()
            expected_destination = ('8.8.8.8', 53)
            self.assertEqual(sock.family, socket.AF_INET)
            self.assertEqual(sock.type, socket.SOCK_STREAM)
            self.assertEqual(destination, expected_destination)

    def _raise_host_unreachable_func(self):
        raise DNSClientException(DNSClientException.HostUnreachableException)

    def test_doesnt_raises_in_result(self):
        result = Result.of(self._raise_host_unreachable_func)
        self.assertEqual(result.error.args[0], DNSClientException.HostUnreachableException)

    def test_record_parsers(self):
        self.assertEqual(RecordTypes.parse(b'\x00\x01'), RecordTypes.A)

    def _test_parse_resource_record_reader(self):
        pass

    def test_transmission_handler_sender(self):
        sock = type('socket', (object,), {
            'send': lambda x: None,
            'connect': lambda x: None
        })
        connection_info = ConnectionInfo('8.8.8.8', 53, socket.SOCK_STREAM, 2)
        dns_transmission_handler = DNSTransmissionHandler()
        r = dns_transmission_handler._send(b'', sock, connection_info)
        ok_none_result = Result.ok(None)
        self.assertEqual(r.is_success, ok_none_result.is_success)
        self.assertEqual(r.error, ok_none_result.error)
        self.assertEqual(r.value, ok_none_result.value)

    def test_transmission_handler_receiver(self):
        sock = type('socket', (object,), {
            'recv': lambda x: b'123',
            'settimeout': lambda x: None
        })
        connection_info = ConnectionInfo('8.8.8.8', 53, socket.SOCK_DGRAM, 2)
        dns_transmission_handler = DNSTransmissionHandler()
        r = dns_transmission_handler._receive(sock, connection_info)
        self.assertEqual(r.value, b'123')

    def test_transmission_handler_request(self):
        transaction = type('', (object,), {'bytes': lambda: b'123'})
        DNSTransmissionHandler._send = MagicMock(return_value=Result.ok(None))
        DNSTransmissionHandler._receive = MagicMock(return_value=Result.ok(b'123'))
        connection_info = ConnectionInfo('8.8.8.8', 53, socket.SOCK_DGRAM, 2)
        result = DNSTransmissionHandler.request(transaction, connection_info)
        self.assertEqual(result.value, b'123')


if __name__ == '__main__':
    unittest.main()
