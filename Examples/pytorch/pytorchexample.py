# This PyTorch image classification example is based off
# https://www.learnopencv.com/pytorch-for-beginners-image-classification-using-pre-trained-models/
from timeit import default_timer as timer
from torchvision import models
import statistics
import torch

EXP_NUM_THREADS = 1
EXP_BATCH_SIZE  = 1

torch.set_num_threads(EXP_NUM_THREADS)

start = timer()
#alexnet = torch.load("pretrained.pt")
alexnet = models.inception_v3(pretrained=True)
end = timer()
model_load_time = end - start

from torchvision import transforms
transform = transforms.Compose([
    transforms.Resize(256),
    transforms.CenterCrop(224),
    transforms.ToTensor(),
    transforms.Normalize(
    mean=[0.485, 0.456, 0.406],
    std=[0.229, 0.224, 0.225]
)])

from PIL import Image
img = Image.open("input.jpg")
img_t = transform(img)
batch_t = torch.unsqueeze(img_t, 0).repeat(EXP_BATCH_SIZE, 1, 1, 1)

alexnet.eval()

# warmup runs
for i in range (0,10):
    out = alexnet(batch_t)

# experiment runs
sample = []
for i in range (0,30):
    start = timer()
    out = alexnet(batch_t)
    end = timer()
    sample.append((end - start))

print(model_load_time, statistics.mean(sample),statistics.stdev(sample))

with open('classes.txt') as f:
    classes = [line.strip() for line in f.readlines()]

_, indices = torch.sort(out, descending=True)
percentage = torch.nn.functional.softmax(out, dim=1)[0] * 100

with open("result.txt", "w") as outfile:
    outfile.write(str([(classes[idx], percentage[idx].item()) for idx in indices[0][:5]]))
