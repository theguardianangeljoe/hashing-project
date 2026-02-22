base_words = [
    "admin", "password", "welcome", "hello", "test", "root",
    "secret", "login", "user", "guest", "manager",
    "dragon", "monkey", "football", "shadow",
    "master", "sunshine", "princess", "superman"
]

numbers = [str(i) for i in range(0, 10000)]
symbols = ["", "!", "@", "#"]

with open("big_wordlist.txt", "w") as f:
    for word in base_words:
        # lowercase
        f.write(word + "\n")

        # Capitalized
        f.write(word.capitalize() + "\n")

        # Uppercase
        f.write(word.upper() + "\n")

        for num in numbers:
            for sym in symbols:
                f.write(word + num + sym + "\n")
                f.write(word.capitalize() + num + sym + "\n")