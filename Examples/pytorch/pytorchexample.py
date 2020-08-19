# This PyTorch image classification example is based off
# https://www.learnopencv.com/pytorch-for-beginners-image-classification-using-pre-trained-models/
from timeit import default_timer as timer
import statistics
import torch
from torchvision import models

torch.set_num_threads(72)

# Load the model from a file
start = timer()
#alexnet = torch.load("pretrained.pt")
alexnet = models.inception_v3(pretrained=True)
end = timer()
model_load_time = end - start

# Prepare a transform to get the input image into a format (e.g., x,y dimensions) the classifier
# expects.
from torchvision import transforms
transform = transforms.Compose([
    transforms.Resize(256),
    transforms.CenterCrop(224),
    transforms.ToTensor(),
    transforms.Normalize(
    mean=[0.485, 0.456, 0.406],
    std=[0.229, 0.224, 0.225]
)])

# Load the image.
from PIL import Image
img = Image.open("input.jpg")

# Apply the transform to the image.
img_t = transform(img)

# Magic (not sure what this does).
batch_t = torch.unsqueeze(img_t, 0)

alexnet.eval()

for i in range (0,3):
    out = alexnet(batch_t)

sample = []
for i in range (0,200):
    start = timer()
    out = alexnet(batch_t)
    end = timer()
    sample.append((end - start))

print(model_load_time, statistics.mean(sample),statistics.stdev(sample))

# Load the classes from disk.
with open('classes.txt') as f:
    classes = [line.strip() for line in f.readlines()]

# Sort the predictions.
_, indices = torch.sort(out, descending=True)

# Convert into percentages.
percentage = torch.nn.functional.softmax(out, dim=1)[0] * 100

# Print the 5 most likely predictions.
with open("result.txt", "w") as outfile:
    outfile.write(str([(classes[idx], percentage[idx].item()) for idx in indices[0][:5]]))
