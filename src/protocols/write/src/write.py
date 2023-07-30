# -*- coding: utf-8 -*-

# @Date    : 2023-05-03
# @Author  : Ziyu Tao

import time
import rsa
from hashlib import md5
from typing import NewType, Self, Final, Callable


Hashkey = NewType('Hashkey', str)


class Metadata:
    key: Hashkey
    feature: Hashkey
    author: Hashkey
    created_at: Final[int]
    size: int

    def __init__(self) -> Self:
        """
        Initializes a new instance of the class.

        Args:
        - self: The instance of the class.

        Returns:
        - self: for chain of method calls.

        Side-effects:
        - Sets the 'created_at' attribute of the instance to the current time.
        """
        self.created_at = time.time()
        return self

    def get_info(self) -> str:
        """
        Returns a string containing information about the feature, author, creation time, and size of the current instance.
        """
        return f'feature:{self.feature};author:{self.author};create_at:{self.created_at};size:{self.size};'

    def __str__(self) -> str:
        return f'key:{self.key};{self.get_info()}'


class RecordBase:
    head: Metadata
    body: str
    key_builder: md5
    __complete: bool


class RecordBuilder(RecordBase):
    def __init__(self, feature: Hashkey) -> Callable[[Hashkey], Self]:
        """
        Initializes an instance of the class with a feature hashkey. The function returns add_author.

        Args:
        - feature: A Hashkey object representing the feature hashkey. 

        Returns:
        - A callable that accepts a Hashkey as author's identity and returns an initialized instance of the class.
        """
        self.meta.feature = feature
        self.meta = Metadata()
        self.key_builder = md5()
        self.__complete = False
        return self.__add_author

    def __add_author(self, author: Hashkey) -> Self:
        """
        Add author to the metadata of the current object.

        Args:
        - author: A hashkey representing the author of the object.

        Returns:
        - The current object with the added author metadata.

        Raises:
        - Exception: If the object is already complete.
        """
        if self.__complete:
            raise Exception('already complete')
        self.meta.author = author
        return self

    def append_body(self, content: str) -> Self:
        """
        Append content to the body of the message being built.

        Args:
        - content (str): The content to append to the message body.

        Returns:
        - Self: The instance of the message being built, to allow chaining of method calls.

        Raises:
        - Exception: If the message has already been marked as complete.
        """
        if self.__complete:
            raise Exception('already complete')
        self.body += content
        encode += content.encode('utf-8')
        self.key_builder.update(encode)
        return self

    def complete(self) -> Self:
        """
        Marks the object as complete and generates a unique key based on the object's current state.

        :return: The completed object.
        :raises Exception: If the object has already been marked as complete.
        """
        if self.__complete:
            raise Exception('already complete')
        self.meta.key = self.key_builder.hexdigest()
        self.__complete = True
        return self

    def result(self) -> str:
        """
        Returns a string representation of the meta information about the function 
        and its body. Raises an exception if the object is not complete.
        """
        if not self.__complete:
            raise Exception('not complete')
        return f'{self.meta.__str__()}body:{self.body}\n'


def write(path: str, feature: Hashkey, author: Hashkey, content: str):
    """
    Write content to a file at the given path.

    Arguments:
    - path: a string representing the path of the file
    - feature: a hashkey representing the feature
    - author: a hashkey representing the author
    - content: a string representing the content to write to the file

    Returns:
    - a hashkey representing the meta key of the record
    
    Example:
    path = 'example.txt'
    feature = 'feature123'
    author = 'author123'
    content = 'example content'
    write(path, feature, author, content)
    """
    with open(path, 'a') as f:
        record = RecordBuilder(feature)(author).append_body(content).complete()
        f.write(record.result())
        return record.meta.key

def write_crypto(path: str, feature: Hashkey, author: Hashkey, content: str, pub_key: string):
    """
    Encrypts the content using the given public key and writes the encrypted data to the specified file.

    Parameters:
        path (str): The path to the file to write the encrypted data to.
        feature (Hashkey): The hash key for the feature.
        author (Hashkey): The hash key for the author.
        content (str): The content to be encrypted.
        pub_key (string): The public key used for encryption.

    Returns:
        The result of the write operation.
    """
    crypto = rsa.encrypt(content.encode(), pub_key)
    with open(path, 'a') as f:
        record = RecordBuilder(feature)(author).append_body(content).complete()
        f.write(rsa.sign(record.encode(), privkey, "SHA-256"))
        return record.meta.key

def write_stream(path: str, feature: Hashkey, author: Hashkey):
    """
    A function that writes a record to a given path.

    Args:
    - path (str): The path to write the record to.
    - feature (Hashkey): The hashkey of the feature to be written.
    - author (Hashkey): The hashkey of the author of the record.

    Returns:
    A tuple consisting of two functions:
    - `append()`: A function that appends content to the record's body.
    - `complete()`: A function that completes the record and writes it to file.

    Example:
    append, complete = write_stream(path, feature, author)
    append(content)
    append(content2)
    key = complete()
    """
    with open(path, 'a') as f:
        record = RecordBuilder(feature)(author)

        def append(content: str):
            """
            Append the content to the record's body.

            Args:
            - content (str): The content to be appended to the record's body.

            Returns:
            - The updated record with the new content appended to its body.
            """
            nonlocal record
            return record.append_body(content)

        def complete():
            """
            Completes the record and writes the result to file.

            Returns:
            The key of the record's meta data.
            """
            nonlocal record
            record.complete()
            f.write(record.result())
            return record.meta.key
        return (append, complete)
