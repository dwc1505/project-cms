import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import { User } from './schemas/user.schema';
import { hashPasswordHelper } from 'src/helper/util';

@Injectable()
export class UsersService {
  constructor(
    @InjectModel(User.name) 
    private userModel: Model<User>) {}

  isEmailExist = async(email: string) => {
    const user =  await this.userModel.exists({email})
    if(user) return true;
    return false;
  }
  async create(createUserDto: CreateUserDto) {
    const {name, email, password,phone,address} = createUserDto;
    const isExist = await this.isEmailExist(email);
    if(isExist){
      throw new BadRequestException(`Email ${email} đã tồn tại.Vui lòng sử dụng email khác`)
    }
    const hashPassword = await hashPasswordHelper(password);
    const user = await this.userModel.create({
      name,email,password: hashPassword,phone,address
    })
    return{
      message: `Thêm thành công user`,
      user
    }
  }

  async findAll() {
    const users = await this.userModel.find();
    return users;
  }

  async findOne(id: string) {
    if (!Types.ObjectId.isValid(id)) {
      throw new NotFoundException(`Không tìm thấy user chứa id ${id}`);
    }

    const user = await this.userModel.findById(id) 
    if (!user) {
      throw new NotFoundException(`Không tìm thấy user chứa id ${id}`);
    }

    return user;
  }

  async update(id: string, updateUserDto: UpdateUserDto) {
    if (!Types.ObjectId.isValid(id)) {
      throw new NotFoundException(`Không tìm thấy user chứa id ${id}`);
    }

    const fieldsToUpdate = updateUserDto;
    const updatedUser = await this.userModel.findByIdAndUpdate(
      id,
      { $set: fieldsToUpdate },
      { new: true }
    );

    if (!updatedUser) {
      throw new NotFoundException(`Không tìm thấy user chứa id ${id}`);
    }

    return {
      message: `Sửa thành công user`,
      updatedUser
    };
  }

  async remove(id: string) {
    if (!Types.ObjectId.isValid(id)) {
      throw new NotFoundException(`Không tìm thấy user chứa id ${id}`);
    }
    const deletedUser = await this.userModel.findByIdAndDelete(id);
    if (!deletedUser) {
      throw new NotFoundException(`Không tìm thấy user chứa id ${id}`);
    }
    return deletedUser;
  }
}
