#!/usr/bin/python

import signal
import argparse
import collections
import subprocess
from cycler import cycler
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.animation as animation
import time
import os
import sys

def get_mem_info():
    return subprocess.check_output('adb shell su root cat /proc/meminfo'.split())

class MemFetcher(dict):
    def __init__(self, names):
        for name in names: self[name] = None
    def update(self):
        lines = get_mem_info().split('\n')
        for line in lines:
            if not line:
                continue
            tokens = line.split()
            if len(tokens) < 3:
                continue
            name = tokens[0][:-1]
            if name not in self:
                continue
            self[name] = int(tokens[1]) * 1024

class MemData(collections.deque):
    def __init__(self, maxlen=None):
        collections.deque.__init__(self, [], maxlen)

    def to_nparray(self, interval):
        return np.array([np.arange(0, interval * len(self), interval), self], dtype=float)


class Field(object):
    def __init__(self, name, memdata, line):
        self.name = name
        self.memdata = memdata
        self.line = line

    def update(self, fetcher, interval):
        self.memdata.append(fetcher[self.name])
        self.line.set_data(self.memdata.to_nparray(interval))

class AnimationData(object):
    def __init__(self, names, plt, width, interval):
        self.fetcher = MemFetcher(names)
        self.fields = []
        self.interval = interval
        for name in names:
            self.fields.append(Field(name, MemData(width), plt.plot([], [], '-')[0]))

    def update(self):
        self.fetcher.update()
        for field in self.fields:
            field.update(self.fetcher, self.interval)

    def get_lines(self):
        return tuple(field.line for field in self.fields)

def animate(num, animation_data):
    animation_data.update()
    return animation_data.get_lines()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--width", type=int, default=1000)
    parser.add_argument("--interval", type=int, default=200) # ms
    parser.add_argument("--names", type=str, nargs='*', default=["MemFree", "MemAvailable"])
    parser.add_argument("--ylim", type=int, nargs=2, default=[3 << 30, 5 << 30])
    parser.add_argument("--out", type=str, default="")
    args = parser.parse_args()


    fig = None
    def handler(signum, frame):
        path = os.path.join(args.out, time.strftime("%Y%m%d_%H%M%S.png", time.localtime()))
        sys.stdout.write("{}\n".format(path))
        sys.stdout.flush()
        fig.savefig(path)
        plt.close()
    signal.signal(signal.SIGUSR1, handler)

    while True:
        fig = plt.figure()

        animation_data = AnimationData(args.names, plt, args.width, args.interval)
        line_ani = animation.FuncAnimation(fig, animate, 25, fargs=(animation_data,),
                                           interval=100, blit=True)
        # line_ani.save('lines.mp4')

        plt.rc('axes', prop_cycle=(cycler('color', ['r', 'g', 'b', 'y'])))
        plt.xlim(0, args.width * args.interval)
        plt.ylim(*args.ylim)
        plt.xlabel('time (ms)')
        plt.ylabel('Bytes'.format(args.interval))
        plt.title(','.join(args.names))
        plt.show()

if __name__ == '__main__':
    main()
