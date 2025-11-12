from scripts.setup import setup
from scripts.worker import setup_workers_assets_gen, build, BuildType

def main(mode:BuildType):
    setup(worker=True)
    setup_workers_assets_gen(mode)
    build(mode)
    
def print_help():
    print("Usage:")
    print("  yarn build -- <build_type>")
    print("")
    print("Available build types:")
    for b in BuildType:
        print(f"  {b.name}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) == 2:
        main(BuildType[sys.argv[1]])
    else:
        print_help()
                  