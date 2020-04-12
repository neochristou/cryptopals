#!/usr/bin/python3
class MT19937:
    def __init__(self, seed = 5489):
        self.__w = 32
        self.__n = 624
        self.__m = 397
        self.__r = 31
        self.__a = 0x9908B0DF
        self.__u = 11
        self.__d = 0xFFFFFFFF
        self.__s = 7
        self.__b = 0x9D2C5680
        self.__t = 15
        self.__c = 0xEFC60000
        self.__l = 18
        self.__f = 1812433253
        self.__mt = [0] * self.__n
        self.__index = self.__n
        self.__LOWER_MASK = self.uint32((1 << self.__r) - 1)
        self.__UPPER_MASK = self.uint32(~self.__LOWER_MASK)

        self.__mt[0] = seed
        for i in range(1, self.__n):
            self.__mt[i] = self.uint32(self.__f * (self.__mt[i-1] ^ (self.__mt[i-1] >> (self.__w - 2))) + i)
        self.__index = 0

    def uint32(self, num):
        return 0xFFFFFFFF & num

    def __twist(self):
        x = (self.__mt[self.__index] & self.__UPPER_MASK) ^ (self.__mt[(self.__index+1) % self.__n] & self.__LOWER_MASK)
        xA = x >> 1
        if x % 2 != 0:
            xA = xA ^ self.__a
        self.__mt[self.__index] = self.__mt[(self.__index + self.__m) % self.__n] ^ xA

    def extract_number(self):
        self.__twist()
        y = self.__mt[self.__index]
        y ^= (y >> self.__u) & self.__d
        y ^= (y << self.__s) & self.__b
        y ^= (y << self.__t) & self.__c
        y ^= y >> self.__l

        self.__index = self.__index + 1

        return self.uint32(y) 

