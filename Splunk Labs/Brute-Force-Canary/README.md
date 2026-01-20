



<img width="1123" height="592" alt="image" src="https://github.com/user-attachments/assets/4a3ff543-cf2a-495c-8d61-849795a5a7e6" />


index=winlogs sourcetype=XmlWinEventLog EventCode=4625 earliest=-60m
| stats count as failed_logons by user
| sort - failed_logons




<img width="1433" height="429" alt="image" src="https://github.com/user-attachments/assets/efb03471-bdd0-417b-9cb6-ac164a61cabb" />



index=winlogs sourcetype=XmlWinEventLog EventCode=4625 earliest=-60m (user="bschultz" OR user="*\\bschultz")
| stats count as failed_logons by user, host
| sort - failed_logons


<img width="1443" height="432" alt="image" src="https://github.com/user-attachments/assets/ce5744f5-1d20-41b0-99b8-d06b6ca7f36e" />





<img width="2545" height="567" alt="image" src="https://github.com/user-attachments/assets/b341ccca-d88b-4885-8a5c-adb9b01e2de1" />


index=winlogs sourcetype=XmlWinEventLog earliest=-60m (EventCode=4624 OR EventCode=4625) user="bschultz"
| eval event_type=case(EventCode=4625, "failure", EventCode=4624, "success")
| stats count(eval(event_type="failure")) as failures count(eval(event_type="success")) as successes by host
| where failures > 0 OR successes > 0

<img width="2555" height="428" alt="image" src="https://github.com/user-attachments/assets/7620c082-45bb-442c-b929-1035b6b8da9e" />


<img width="493" height="747" alt="image" src="https://github.com/user-attachments/assets/06bc599c-4f44-4db4-b0fe-63c0163a9aa9" />

