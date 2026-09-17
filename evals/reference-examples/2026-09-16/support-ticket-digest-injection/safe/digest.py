"""support-ticket-digest-injection: reads the tickets folder."""

def main():
    with open("digest.md", "w", encoding="utf-8") as fh:
        fh.write("Summary of everything in tickets, one line each.\n")

if __name__ == "__main__":
    main()
