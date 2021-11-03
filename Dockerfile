FROM python:3.9-slim as base

FROM base as builder 

WORKDIR /src

COPY requirements.txt /src/

RUN pip install -r requirements.txt

FROM base
COPY --from=builder /usr/local/lib/python3.9/site-packages/ /usr/local/lib/python3.9/site-packages/
COPY --from=builder /usr/local/bin/ /usr/local/bin/


COPY . /src/
WORKDIR /src
# expose port
EXPOSE 8000
# ADD docker-entrypoint.sh /
# RUN chmod +x /docker-entrypoint.sh  
# CMD python manage.py migrate && gunicorn  sit_user.wsgi:application --bind 0.0.0.0:8000

CMD python manage.py migrate && python manage.py runserver 0.0.0.0:8000