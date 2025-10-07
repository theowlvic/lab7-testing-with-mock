from unittest import mock

import pytest

from presidio_anonymizer.operators import OperatorType
from presidio_anonymizer.operators import Encrypt, AESCipher
from presidio_anonymizer.entities import InvalidParamError



@mock.patch.object(AESCipher, "encrypt")
def test_given_anonymize_then_aes_encrypt_called_and_its_result_is_returned(
    mock_encrypt,
):
    expected_anonymized_text = "encrypted_text"
    mock_encrypt.return_value = expected_anonymized_text

    anonymized_text = Encrypt().operate(text="text", params={"key": "key"})

    assert anonymized_text == expected_anonymized_text


@mock.patch.object(AESCipher, "encrypt")
def test_given_anonymize_with_bytes_key_then_aes_encrypt_result_is_returned(
        mock_encrypt,
):
    expected_anonymized_text = "encrypted_text"
    mock_encrypt.return_value = expected_anonymized_text

    anonymized_text = Encrypt().operate(text="text",
                                        params={"key": b'1111111111111111'})

    assert anonymized_text == expected_anonymized_text


def test_given_verifying_an_valid_length_key_no_exceptions_raised():
    Encrypt().validate(params={"key": "128bitslengthkey"})


def test_given_verifying_an_valid_length_bytes_key_no_exceptions_raised():
    Encrypt().validate(params={"key": b'1111111111111111'})


def test_given_verifying_an_invalid_length_key_then_ipe_raised():
    with pytest.raises(
        InvalidParamError,
        match="Invalid input, key must be of length 128, 192 or 256 bits",
    ):
        Encrypt().validate(params={"key": "key"})

@mock.patch.object(AESCipher, "is_valid_key_size") # hint: replace encrypt with the method that you want to mock
def test_given_verifying_an_invalid_length_bytes_key_then_ipe_raised(mock_is_valid_key_size): # hint: replace mock_encrypt with a proper name for your mocker
    # Here: add setup for mocking
    mock_is_valid_key_size.return_value = False  # This sets what the mock returns
    with pytest.raises(
        InvalidParamError,
        match="Invalid input, key must be of length 128, 192 or 256 bits",
    ):
        Encrypt().validate(params={"key": b'1111111111111111'})
    mock_is_valid_key_size.assert_called_once_with(b'1111111111111111')

def test_operator_name():
    assert Encrypt().operator_name() == 'encrypt'

def test_operator_type():
    assert Encrypt().operator_type() == OperatorType.Anonymize


@pytest.mark.parametrize(
    "key",
    [
        # String keys
        "1234567890123456",  # 128 bits (16 bytes)
        "123456789012345678901234",  # 192 bits (24 bytes)
        "12345678901234567890123456789012",  # 256 bits (32 bytes)
        # Bytes keys
        b"1234567890123456",  # 128 bits (16 bytes)
        b"123456789012345678901234",  # 192 bits (24 bytes)
        b"12345678901234567890123456789012",  # 256 bits (32 bytes)
    ],
)
def test_valid_keys(key):
    # Should not raise any exception for valid key sizes
    Encrypt().validate(params={"key": key})