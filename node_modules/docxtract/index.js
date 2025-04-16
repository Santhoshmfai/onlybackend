#!/usr/bin/env node

const fs = require('fs')
const mammoth = require("mammoth")
const path = require('path')
const inquirer = require('inquirer')

// EXTRACT RAW TEXT
const extractText = (arr, input, output) => {

  for (file of arr) {
    const fileArr = file.split('.')
    const filename = fileArr[0]
    const extension = fileArr.pop()

    if (extension == 'docx') {
      async function convert() {
        try {
          var data = await mammoth.extractRawText({ path: path.join(input, file) })
          const text = data.value
          fs.writeFileSync(path.join(output, `${filename}.txt`), text)
        } catch (err) {
          console.log(err)
        }
      }
      convert()
    }
  }
}

//CONVERT TO HTML
const convertToHtml = (arr, input, output) => {

  for (file of arr) {
    const fileArr = file.split('.')
    const filename = fileArr[0]
    const extension = fileArr.pop()

    if (extension == 'docx') {
      async function convert() {
        try {
          var data = await mammoth.convertToHtml({ path: path.join(input, file) })
          const html = data.value
          fs.writeFileSync(path.join(output, `${filename}.html`), html)
        } catch (err) {
          console.log(err)
        }
      }
      convert()
    }
  }
}

const methodPrompt = inquirer.createPromptModule()

//QUESTIONS ASKED TO USER
const questions = [
  {
    type: 'list',
    name: 'Method',
    message: 'What do you want to do with the docx files? Convert to...',
    choices: [
      'text',
      'html'
    ]
  },
  {
    type: 'input',
    name: 'inputFolder',
    message: '\n\nWhich folder do you want to be converted? (The files in this folder will not be changed)\nEnter the input folder path:\n',
    default: 'C:\\Users\\user\\Desktop\\inputFolder'
  },
  {
    type: 'input',
    name: 'outputFolder',
    message: '\n\nIn which folder do you want the converted files to be saved? (The converted files will be saved here)\nEnter the output folder path:\n',
    default: 'C:\\Users\\user\\Desktop\\outputFolder'
  }
]

//HANDLE ANSWERS
methodPrompt(questions)
  .then(answers => {
    //DECONSTRUCT ANSWERS FROM PROMPT ANSWERS
    const { Method, inputFolder, outputFolder } = answers

    //READ FILES IN INPUT FOLDER
    const files = fs.readdirSync(inputFolder)

    if (Method == 'text') {
      extractText(files, inputFolder, outputFolder)
      console.log("\n\n\nThe docx files have been converted to text 🙂")
    }

    if (Method == 'html') {
      convertToHtml(files, inputFolder, outputFolder)
      console.log("\n\n\nThe docx files have been converted to html 🙂")
    }
  })
  .catch(err => console.log("Sorry, something went wrong ☹️ \nPlease check your paths and try again.\n"))









