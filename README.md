# PasswordCracker
Basic brute force password hash cracker designed for a cybersecurity class.

When provided with a wordlist and a file of password hashes, the program can crack passwords that follow specific rules. The rules are:

1) Any seven character word from a word list, with the first letter capitalized and a single-digit number appended to the end
2) A four digit password with at least one of the following special characters in the beginning: *, ~, !, #
3) A five character word from a word list. Any instance of the letter a CAN be replaced with an @, and any l with 1, but accounts for any combination of these replacements.
4) Any number combination between 000000 to 999999.
5) Any single word from a wordlist

To run the program, the full filepaths to the wordlist and password hash files must be provided. 


