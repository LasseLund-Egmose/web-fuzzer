from dataclasses import dataclass

from .wordlists import wordlist_build

@dataclass
class FuzzParameter():
    name: str
    wordlists: list

    def combined_wordlist(self, encoders, data_dir, args):
        return wordlist_build(self.wordlists, encoders, data_dir, args)

@dataclass
class FuzzType():
    params: list
    encoders: list
    required_args: list

    def command_args(self, data_dir, args):
        params_wordlists = [(p, p.combined_wordlist(self.encoders, data_dir, args)) for p in self.params]

        command_args = ""
        for param, wordlist in params_wordlists:
            command_args += f" -w {wordlist}:{param.name}"
            
        yield command_args

@dataclass(frozen=True)
class ScanResult():
    payloads: set
    url: str
    status: int
    length: int
    words: int
    lines: int
    content_type: str
    duration: int
    response_raw: bytes