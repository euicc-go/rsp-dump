from enum import Enum, auto
from scripts.utils import run_command

class BuildType(Enum):
    go = auto()
    tinygo = auto()

def setup_workers_assets_gen(mode:BuildType):
    cmd = [
        "go", "run",
        "github.com/syumai/workers/cmd/workers-assets-gen",
        f"-mode={mode.name}",
        "-o", "./dist/rsp-dump-cf-workers_js_wasm"
    ]
    return run_command(cmd)

def build_go():
    env = {
        'CGO_ENABLED': '0',
        'GOOS': 'js',
        'GOARCH': 'wasm'
    }
    cmd = [
        "go", "build",
        "-trimpath",
        '-ldflags', "-s -w",
        "-o", "./dist/rsp-dump-cf-workers_js_wasm/app.wasm",
        "./cmd/rsp-dump-cf-workers"
    ]
    return run_command(cmd, env=env)

def build_tinygo():
    cmd = [
        "tinygo", "build",
        "-o", "./dist/rsp-dump-cf-workers_js_wasm/app.wasm",
        "-target", "wasm",
        "-no-debug",
        "./cmd/rsp-dump-cf-workers"
    ]
    return run_command(cmd)

def build(mode:BuildType):
    match mode:
        case BuildType.go:
            return build_go()
        case BuildType.tinygo:
            return build_tinygo()
        case _:
            raise RuntimeError("Invalid build mode")
