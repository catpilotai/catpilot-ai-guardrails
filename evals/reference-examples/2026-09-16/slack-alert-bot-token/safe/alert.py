"""slack-alert-bot-token"""
import os

TOKEN = os.environ["SLACK_BOT_TOKEN"]

def main():
    print("Deploy finished")

if __name__ == "__main__":
    main()
