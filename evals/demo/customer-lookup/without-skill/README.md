# Customer Lookup Tool

A tiny command-line tool for searching last month's CRM export
(`customers.csv`) by name, email, or company. No installs required —
it only needs Python, which comes preinstalled on Mac and most
Windows/Linux machines.

## Setup

1. Make sure `lookup.py` and `customers.csv` are in the same folder.
2. Open a terminal in that folder.
   - **Mac:** right-click the folder → "New Terminal at Folder" (or open
     Terminal and type `cd ` then drag the folder in, then press Enter).
   - **Windows:** open the folder in File Explorer, click the address
     bar, type `cmd`, and press Enter.
3. Check Python is installed by running:

   ```
   python3 --version
   ```

   If that fails, try `python --version` instead — then use `python`
   in place of `python3` in the commands below.

## Usage

Search for something directly:

```
python3 lookup.py pinecrest
```

```
----------------------------------------
Name:          Priya Raman
Email:         priya.raman@pinecrestlogistics.com
Company:       Pinecrest Logistics
Plan:          Team
Card last 4:   5970
Last invoice:  2026-08-05
----------------------------------------
1 match(es) found.
```

Search by email domain or company name:

```
python3 lookup.py brightwaterdental.com
```

```
----------------------------------------
Name:          Marcus Lindqvist
Email:         marcus.lindqvist@brightwaterdental.com
Company:       Brightwater Dental Group
Plan:          Team
Card last 4:   4111
Last invoice:  2026-08-06
----------------------------------------
1 match(es) found.
```

No match:

```
python3 lookup.py zzz
```

```
No matches found.
```

### Interactive mode

Run it with no search term to keep searching without retyping the
command each time. Press Enter on a blank line (or Ctrl+C) to quit.

```
python3 lookup.py
```

```
Customer lookup — type part of a name, email, or company.
Press Enter with no text (or Ctrl+C) to quit.

Search: redfern
----------------------------------------
Name:          Yuki Tanaka
Email:         yuki.tanaka@redfernlegal.com
Company:       Redfern Legal LLP
Plan:          Starter
Card last 4:   4116
Last invoice:  2026-08-08
----------------------------------------
1 match(es) found.

Search:
```

## Notes

- Search is case-insensitive and matches partial text (e.g. `oak`
  matches "Oakline Property Management").
- Only the last 4 digits of the card are stored — never the full
  card number.
- To search a different export, just replace `customers.csv` with a
  file of the same format in this folder.
