import base64

# Open and read the image file
with open('bg.jpg', 'rb') as image_file:
    # Encode the image as Base64
    base64_image_data = base64.b64encode(image_file.read()).decode()

# Print the encoded data, which you can copy and paste into your script
print(base64_image_data)
