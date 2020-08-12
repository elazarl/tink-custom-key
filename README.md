This is an example of how to use a custom key with [tink](https://github.com/google/tink).

Do NOT use this at home. This is ****insecure*, and just for educational purposes.

The main idea here is, write your own key manager that supplies a custom key
in this case, we insecurely provide a constant key 0102030405060708090a0b0c0d0e0f10.
