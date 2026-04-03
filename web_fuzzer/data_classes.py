from dataclasses import dataclass

from .wordlists import wordlist_build

@dataclass
class FuzzParameter():
    name: str
    wordlists: list

    def combined_wordlist(self, encoders, override_list, data_dir, args):
        return wordlist_build([override_list] if override_list else self.wordlists, encoders, data_dir, args)

@dataclass
class FuzzType():
    params: list
    encoders: list
    required_args: list

    def command_args(self, override_params, data_dir, args):
        params_wordlists = [(p, p.combined_wordlist(self.encoders, override_params.get(p.name), data_dir, args)) for p in self.params]

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
    resultfile_path: str