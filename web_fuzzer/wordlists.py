import os
import random
import string

def random_str(len: int):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=len))

def wordlist_read(wordlist_file, modifier):
    with open(wordlist_file, "rb") as f:
        for w in f.read().splitlines():
            yield modifier(w)

def wordlist_read_callable(wordlist_file, modifier = None):
    return lambda args: wordlist_read(wordlist_file, modifier if modifier != None else (lambda w: w))

def wordlist_strip_prefix(wordlist_file: str, prefixes):
    def strip_prefix(w):
        for p in prefixes:
            if w[:len(p)] == p:
                return w[len(p):]
        
        return w

    return wordlist_read_callable(wordlist_file, strip_prefix)

def wordlists_load(wordlist_files, args):
    full_wordlist = []
    seen_words = set()

    for wordlist_reader in wordlist_files:
        if isinstance(wordlist_reader, str):
            wordlist_reader = wordlist_read_callable(wordlist_reader)
        
        for w in wordlist_reader(args):
            try:
                w = w.strip().decode("utf-8")
                if len(w) == 0 or w[0] == "#":
                    continue

                if w in seen_words:
                    continue

                seen_words.add(w)
                full_wordlist.append(w)
            
            except UnicodeDecodeError as e:
                print(f"Error processing word {w}: {e}")

    return full_wordlist

def wordlists_product(wordlist_1: list, wordlist_2: list):
    full_wordlist = []
    seen_words = set()

    if "" not in wordlist_1:
        wordlist_1 = [""] + wordlist_1
    
    if "" not in wordlist_2:
        wordlist_2 = [""] + wordlist_2

    for w1 in wordlist_1:
        for w2 in wordlist_2:
            w = w1 + w2

            if w in seen_words:
                continue

            seen_words.add(w)
            full_wordlist.append(w)
    
    return full_wordlist

def wordlist_build(wordlist_files: list, encoders, data_dir, args):
    full_wordlist = []

    for wordlist_files in wordlist_files:
        if isinstance(wordlist_files, str) or callable(wordlist_files):
            wordlist_files = [wordlist_files]

        wordlist = wordlists_load(wordlist_files, args)
        full_wordlist = wordlists_product(full_wordlist, wordlist)
    
    full_wordlist_encoded = []
    for w in full_wordlist:
        for encoder in encoders:
            for output in encoder(w):
                full_wordlist_encoded.append(output)

    full_wordlist_file = os.path.join(data_dir, f"wordlist-{random_str(16)}.txt")
    with open(full_wordlist_file, "w") as f:
        f.write("\n".join(full_wordlist_encoded))
    
    return full_wordlist_file