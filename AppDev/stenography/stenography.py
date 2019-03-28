#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Mar 30 17:19:50 2017
@author: n0_ob
"""

import sys
from PIL import Image


def txt_encode(imp, text, f_out_filename):
    Im = Image.open(imp)

    pixel = Im.load()
    pixel[0, 0] = (len(text) % 256, (len(text) // 256) % 256, (len(text) // 65536))

    for i in range(1, len(text) + 1):
        k = list(pixel[0, i])
        k[0] = int(k[0] / 10) * 10 + ord(text[i - 1]) // 100
        k[1] = int(k[1] / 10) * 10 + ((ord(text[i - 1]) // 10) % 10)
        k[2] = int(k[2] / 10) * 10 + ord(text[i - 1]) % 10
        # print(pixel[0,i],k,ord(text[i-1]))
        pixel[0, i] = tuple(k)
    Im.save(f_out_filename)


def txt_decode(imp):
    Im = Image.open(imp)
    # Im=Im.convert('RGB')
    pixels = Im.load()
    size = (pixels[0, 0][0]) + (pixels[0, 0][1]) * 256 + (pixels[0, 0][2]) * 65536
    t = []
    for i in range(1, size + 1):
        # print(pixels[0,i])
        t.append(chr((pixels[0, i][0] % 10) * 100 + (pixels[0, i][1] % 10) * 10 + (pixels[0, i][2] % 10)))
    te = "".join(t)
    print(te)


# Main()
if __name__ == "__main__":

    print("do you want to encode text into an image or do you want to decode an image ?\n1:encode \n2:decode")
    temp = input()
    try:
        if temp == "2":

            print("choose file to decode ")
            img_f_name = input(">>> ")
            txt_decode(img_f_name)

        elif temp.lower() == "1":

            print("give photo where you want to hide text in (with extension)")
            img_f_name = input(">>> ")
            print("give text to encode ")
            text = input(">>> ")
            print("give the output file a name (no extension)")
            output_file_name = input(">>> ")
            output_file_name = output_file_name + ".png"
            txt_encode(img_f_name, text, output_file_name)
    except FileNotFoundError as e:
        print("File not found, please rerun the program")
