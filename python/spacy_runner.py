#!/usr/bin/env python3
import json

def print_log_output(type:str, message:str, data):
    p = json.dumps({"type": type, "message": message, "data": data})
    print(p)

try:
    print_log_output("log", "Importing required libraries", None)

    import sys
    import en_core_web_sm
    print_log_output("log", "Successfully imported required libraries", None)

    nlp = en_core_web_sm.load() # need to find some solution to speedup loading
    print_log_output("log", "Successfully loaded model", None)

    for i in sys.stdin:
        try:
            print_log_output("log", "Processing text 1", {"text": i})
            i = i.strip()
            print_log_output("log", "Processing text 2", {"text": i})
            if i == "EXIT":
                break

            print_log_output("log", "Processing text", {"text": i})
            doc = nlp(i)
            print_log_output("output", "Successfully processed text", {"text": i, "entities": [{ "text" :ent.text, "label": ent.label_} for ent in doc.ents]})
        except ImportError:
            print_log_output("error", "Failed to import required libraries", None)
        except Exception as e:
            print_log_output("error", str(e), None)

except ImportError:
    print_log_output("error", "Failed to import required libraries", None)
except Exception as e:
    print_log_output("error", str(e), None)
finally:
    print_log_output("exit", "Exiting", None)
