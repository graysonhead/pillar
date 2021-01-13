from pillar.cli import CLI
import sys


def main():
    cli = CLI(sys.argv[1:])
    cli.run()


if __name__ == "__main__":
    main()
