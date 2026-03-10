#!/bin/sh

# to convert the tabular.raygun paths to use the custom path


sed 's|/v1/data/portcullis/tabular/decision|/v1/data/portcullis/custom/decision|g' tabular.raygun > custom.raygun


