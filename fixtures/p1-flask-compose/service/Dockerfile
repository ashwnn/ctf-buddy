FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN pip install --no-cache-dir "flask==3.0.3" "gunicorn==22.0.0"

WORKDIR /srv/app

COPY app.py seed.py ./
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# The canary sits OUTSIDE the download root. It is the target of the tier-3
# negative probe: a correct patch makes it unreachable, and nothing else in the
# fixture depends on it.
RUN mkdir -p /srv/app/uploads /data \
 && printf 'welcome to the fixture\n' > /srv/app/uploads/welcome.txt \
 && printf 'FIXTURE_CANARY_value_outside_the_download_root\n' > /srv/canary.txt

EXPOSE 8000
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
