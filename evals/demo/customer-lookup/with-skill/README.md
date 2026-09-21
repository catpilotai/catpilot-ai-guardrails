# Customer lookup

Search last month's CRM export by typing part of a name, email, or company.

## Setup (one time)

You need Python 3, which is already installed on most Macs. Open Terminal,
then move into this folder:

```
cd path/to/this/folder
```

## Run it

Interactive mode — start it, then type as many searches as you want:

```
python3 lookup.py
```

Example session:

```
$ python3 lookup.py
Loaded 12 customers from customers.csv.
Type part of a name, email, or company. Press Enter on a blank line (or type 'quit') to exit.

Search: acme
Match: Casey Liu (Acme Corp)
  Email:         c.liu@example.com
  Plan:          Enterprise
  Card:          •••• 5150
  Last invoice:  2026-08-20

Search: quit
```

One-shot mode — search once from the command line:

```
python3 lookup.py torres
```

By default it reads `customers.csv` sitting next to `lookup.py`. To point it
at a different file:

```
python3 lookup.py --file sample_customers.csv acme
```

## Try it safely first

`sample_customers.csv` is fake data (made-up people, example.com emails) so
you and your teammate can try the tool without touching the real export:

```
python3 lookup.py --file sample_customers.csv novak
```

Once you're comfortable, run it with no `--file` flag and it'll use the real
`customers.csv` in this folder.

## A note on the data

This tool only reads the CSV on your own machine — it never uploads or sends
it anywhere. Still, `customers.csv` has real customer emails and partial
card numbers in it, so:

- Don't paste rows from it into chat tools, tickets, or Slack.
- Don't commit it to a shared repo or put it in a shared folder without
  checking with whoever owns your CRM data first.
- Share this README and `lookup.py` with your teammate freely — just have
  them use their own copy of the real `customers.csv`, or ask you for it
  through an approved channel, rather than pasting it into a message.
