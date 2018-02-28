#include <ImageMagick-6/wand/MagickWand.h>

#include "convert-w-sb.h"

void convert_image(char *infile, char *outfile) {
  // proxy this for ConvertImageCommand
  MagickWand *image = NULL;
  PixelWand *target = NULL;
  PixelWand *fill = NULL;

  // Convert 40% to double
  const double fuzz = 40 * QuantumRange / 100;

  MagickWandGenesis();

  target = NewPixelWand();
  fill = NewPixelWand();
  image = NewMagickWand();

  // Load image
  MagickReadImage(image, infile);

  // Set Colors
  PixelSetColor(target, "rgb(65535, 65535, 65535)");
  PixelSetColor(fill, "rgb(53456, 35209, 30583)");

  // Apply effect(wand,0.40);
  MagickOpaquePaintImage(image, target, fill, fuzz, MagickFalse);

  // Save image
  MagickWriteImages(image, outfile, MagickTrue);

  // Clean up
  image = DestroyMagickWand(image);
  MagickWandTerminus();
}
