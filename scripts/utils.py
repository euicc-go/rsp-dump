from typing import Callable
from enum import Enum, auto
from pathlib import Path

class TaskType(Enum):
    single_content_multiple_files = auto()
    multiple_contents_multiple_files = auto()
    
def get_text_from_url(url:str) -> str:
    import urllib.request
    with urllib.request.urlopen(url) as response:
        return response.read().decode('utf-8')

class Manager:
    def __init__(self, download_func: Callable[[str], str] = get_text_from_url):
        self.download_func = download_func
        self._cache: dict[str, str] = {}
        self._processed_files: set[Path] = set()
    
    def download_once(self, url: str) -> str:
        if url in self._cache:
            return self._cache[url]
        
        print(f"Downloading: {url}")
        content = self.download_func(url)
        self._cache[url] = content
        return content
    
    def write_file_if_missing(self, path: Path, content_getter) -> bool:
        if path in self._processed_files:
            return False
            
        if path.exists():
            print(f"Skipped (exists): {path}")
            self._processed_files.add(path)
            return False
        
        path.parent.mkdir(parents=True, exist_ok=True)
        content = content_getter()
        path.write_text(content, encoding="utf-8")
        print(f"Written: {path}")
        self._processed_files.add(path)
        return True
    
    def batch_process(self, tasks: list[dict]) -> None:
        urls_to_download: set[str] = set()
        
        for task in tasks:
            if task["type"] == TaskType.single_content_multiple_files:
                all_exist = all(Path(file_path).exists() for file_path in task["target_files"])
                if not all_exist:
                    urls_to_download.add(task["url"])
            
            elif task["type"] == TaskType.multiple_contents_multiple_files:
                for item in task["items"]:
                    all_exist = all(
                        Path(file_pattern.format(**item)).exists() 
                        for file_pattern in task["target_patterns"]
                    )
                    if not all_exist:
                        urls_to_download.add(item["url"])
        
        for url in urls_to_download:
            self.download_once(url)
        
        for task in tasks:
            if task["type"] == TaskType.single_content_multiple_files:
                content = self._cache.get(task["url"])
                if content:
                    if "processor" in task:
                        content = task["processor"](content)
                    
                    for file_path in task["target_files"]:
                        path = Path(file_path)
                        self.write_file_if_missing(
                            path, 
                            lambda c=content: c
                        )
            
            elif task["type"] == TaskType.multiple_contents_multiple_files:
                for item in task["items"]:
                    content = self._cache.get(item["url"])
                    if content:
                        if "processor" in task:
                            content = task["processor"](content, item)
                        
                        for file_pattern in task["target_patterns"]:
                            file_path = file_pattern.format(**item)
                            path = Path(file_path)
                            self.write_file_if_missing(
                                path,
                                lambda c=content: c
                            )