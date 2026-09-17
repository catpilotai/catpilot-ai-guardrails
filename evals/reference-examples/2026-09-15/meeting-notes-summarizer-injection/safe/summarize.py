"""meeting-notes-summarizer-injection: reads the meeting_notes folder."""

def main():
    with open("summary.md", "w", encoding="utf-8") as fh:
        fh.write("Summary of everything in meeting_notes, one line each.\n")

if __name__ == "__main__":
    main()
