# Module 6: Incident Detection and Identification

## Passive Incident Alerting

### Using Alerts as a Starting Point

Use an alert as your starting point and move forwards/backwards.

### How to Correlate Alerts

Are they logically related? Look further into 'em to confirm.

## Active Incident Discovery

### Threat Hunting

SOCs react, Threat Hunters proactively hunt.

### Third-Party Sources

Third parties sometimes provide alerts of suspicious activity.

## Identifying False Positives

### Understanding the Impact of False Positives

They waste time, increasing _alert fatigue_.

### Understanding Incident vs Event

* A cyber security **event** is an observable occurrence in a system or network that may have an impact on an organization.
* A cyber security **incident** is an event or a set of events that have a negative impact on the security of an organization.
* A **precursor** is an event that is a sign of potential future incidents.
* An **indicator** is evidence that an incident may have already occurred or is currently occurring.

### False Positive Case Studies

_This was a walkthrough of a challenge._

### Automating Away False Positives

Remove old alerts, adjust thresholds, etc.

## Identifying Attack Chains

### Identifying Single-Host Compromise

Make a list of CVEs, search on them.

### Identifying a Full Compromise

No big difference, again, follow the event timeline.
