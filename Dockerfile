FROM ubuntu:20.04

# Disable dialog questions
RUN echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections

# Install git, sudo
RUN apt update \
 && apt install -y \
    git sudo tig fish curl gnupg

RUN echo "deb https://repo.scala-sbt.org/scalasbt/debian all main" | sudo tee /etc/apt/sources.list.d/sbt.list
RUN echo "deb https://repo.scala-sbt.org/scalasbt/debian /" | sudo tee /etc/apt/sources.list.d/sbt_old.list
RUN curl -sL "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x2EE0EA64E40A89B84B2DF73499E82A75642AC823" | sudo apt-key add
RUN sudo apt-get update

# Install specdoctor, it takes about 1 hour
WORKDIR "/root"

RUN git clone https://github.com/vusec/specdoctor.git \
 && cd specdoctor \
 && echo "y" | ./setup.sh

ENTRYPOINT ["/bin/bash"]
