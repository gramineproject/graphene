## PyTorch Base Example

We start with an example inferencing python script written with PyTorch.

Go to the directory that contains [Graphene repository](https://github.com/oscarlab/graphene) you've cloned in the previous section.
```bash
cd <graphene repository>
```

There is `Examples` directory containing example workloads. Go to `Examples/pytorch`

```bash
cd Examples/pytorch
```

The directory contains a python script `pytorchexample.py` and relevant files.
The script reads a [pretrained model](https://pytorch.org/docs/stable/torchvision/models.html)  of AlexNet, and an image `input.jpg`, and infers the class of an object in the image.
Then, the script writes the top-5 classification result to a file `result.txt`.

To run the python script, install required packages for the script.

```bash
sudo apt-get install python3-pip lsb-release
pip3 install --user torchvision
```

Next, download and save the pre-trained model.

```bash
make download_model
```
This uses `download-pretrained-model.py` to download a pretrained model and saves it as a serialized file `alexnet-pretrained.pt`. See [Saving and Loading Models in PyTorch](https://pytorch.org/tutorials/beginner/saving_loading_models.html) for more details.

Now, you can simply run following command to run the script

```bash
python3 pytorchexample.py
```

This will write the classification results to `result.txt`.

In later sections, we will run exactly the same Python script, but inside SGX enclaves.
