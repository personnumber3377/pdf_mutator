#!/bin/python3

from mutator import dprint
import mutator as mut
import random
import pikepdf
import io

mut.DEBUG = True # Set debugging to true...

# This file is for testing the mutator itself...

def load_test_pdf_file(fn: str) -> bytes: # Loads a bytebuffer from a filename
	fh = open(fn, "rb")
	data = fh.read()
	fh.close()
	return data

def test_replace_stream():

	# pdf = pikepdf.open(io.BytesIO(buf))

	# Set deterministic seed...
	random.seed(123)

	rng = random.Random(3)

	test_pdf_data = load_test_pdf_file("./test.pdf")

	pdf = pikepdf.open(io.BytesIO(test_pdf_data)) # Load with pikepdf

	'''
	target = choose_target_object(pdf, rng)
		if target is None:
			raise RuntimeError("no candidate objects found for replacement")
		sample_py = rng.choice(_resources_db)
		ok = replace_object_with_sample(pdf, target, sample_py, rng)
	'''

	t = mut.choose_target_object(pdf, rng)

	dprint(t)



def tests():

	test_replace_stream()

	return

if __name__=="__main__":
	tests()
	exit()
