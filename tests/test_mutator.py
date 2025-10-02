#!/bin/python3

from mutator import dprint
import mutator as mut
import random
import pikepdf
import io

mut.DEBUG = True # Set debugging to true...

THRESHOLD = 10000

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

	# what_to_replace_with = random.Random(4).choice(mut._resources_db)
	what_to_replace_with = None
	for thing in mut._resources_db: # Iterate over the shit...
		if thing["__type__"] == "stream":
			print("poopoo")
			# dprint(thing)
			# if thing["stream_bytes"] == b"": # Empty stuff..
			# 	dprint("Empty!!!")
			# print("qq")
			if len(thing["stream_bytes"]) > THRESHOLD:
				what_to_replace_with = thing
				break
	
	# Stuff...
	assert what_to_replace_with != None
	dprint(what_to_replace_with)

	# Now call the replace...

	ok = mut.replace_object_with_sample(pdf, t, what_to_replace_with, None) # random.Random(1))
	
	assert ok

	# Now save the thing...

	# Save mutated PDF to bytes
	out_buf = io.BytesIO()
	try:
		pdf.save(out_buf, linearize=False, compress_streams=False)
	except Exception as e:
		raise RuntimeError("pikepdf.save failed: %s" % e)
	data = out_buf.getvalue()
	# if len(data) > max_size:
	# 	data = data[:max_size]
	# return data


	fh = open("stuff.pdf", "wb")
	fh.write(data)
	fh.close()

	return


def test_no_empty_elements_in_dict():
	for thing in mut._resources_db: # Iterate over the shit...
		if thing["__type__"] == "stream":
			# dprint(thing)
			# if thing["stream_bytes"] == b"": # Empty stuff..
			# 	dprint("Empty!!!")
			# print("qq")
			if len(thing["stream_bytes"]) == 0:
				assert False
	return


def tests():

	# Initialize mutator...

	mut.init(0) # Call the init function...

	test_no_empty_elements_in_dict() # Check that there are no empty elements in the dictionary which we have constructed...
	test_replace_stream()

	# Maybe add a function to list named things aka a test for collect_named_objects ???

	

	return

if __name__=="__main__":
	tests()
	exit()
